/* -*- mode: C; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/*
 * Copyright (c) 2010  litl, LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <locale.h>

#include <jsdbgapi.h>
#include <jsscript.h>

#include <util/error.h>
#include <util/log.h>
#include <gjs/gjs.h>

#include "debugger.h"
#include "jsapi-util.h"

/* An integrated gjs debugger.  A simple line protocol is exposed over
 * a TCP socket (port 5580 by default).  The network-facing parts run
 * entirely in their own thread with their own GMainContext and main
 * loop.  Therefore, interacting with the debugger is totally
 * independent of the main thread executing JS, will never block, and
 * doesn't require a gjs main loop to be running.
 *
 * The debugger can have breakpoints set via the TCP protocol, or can
 * break automatically when it encounters the "debugger" JavaScript
 * statement.
 *
 * The commands supported by the debugger include:
 *
 * break <file> <line>
 *   Create a breakpoint at the given file and line.  Prints an error
 *   message if it fails.
 *
 * delete <file> <line>
 *   Delete a breakpoint at the given file and line.  Prints an error
 *   message if it fails.
 *
 * stop
 *   Instructs the runtime to stop execution the next time the JS
 *   runtime is invoked.  This only affects JavaScript code, so any
 *   native code (for example, a glib main loop) will continue to run
 *   until and unless some JavaScript code is later run.
 *
 * continue
 *   Instructs the runtime to resume execution immediately.
 *
 * step
 *   Step into a single line of code.  Will descend into functions.
 *
 * next
 *   Step over a single line of code.  Will skip over functions.
 *
 * finish
 *   Step out of the current function.  Will print the return value of the
 *   function.
 *
 * stack
 *   Print the current stack trace
 *
 * locals [frame]
 *   Print the local variables at the given stack frame.  If frame is
 *   omitted, use whatever the current stack frame.
 *
 * eval [frame] <expr>
 *   Evaluate an expression at the current or optionally given stack
 *   frame.  The return value of the expression is displayed.
 *
 * status
 *   Prints whether the runtime is running or suspended.
 *
 * Most commands do not themselves print any messages, but many (like
 * stop, step, etc.) do cause state changes which cause messages to be
 * sent over the TCP socket.  Some of them include:
 *
 * stopped <file> <line>
 *   Any time execution is stopped, the file and line are given.
 *
 * running
 *   Displayed in response to the status command if the runtime is
 *   not suspended.
 *
 * stack <num> <function> <file:line>
 *   The stack trace returned by the stack command.  Terminated by
 *   "stack end".
 *
 * local <name> <type> <value>
 *   A local variable returned by the locals command.
 *
 * ret <value>
 *   The result of an eval or finish command.
 *
 * error <message>
 *   An error is returned from a command.
 *
 */

typedef enum {
    INTERRUPT_NONE = 0,
    INTERRUPT_STOP,
    INTERRUPT_STEP,
    INTERRUPT_NEXT,
    INTERRUPT_FINISH
} GjsInterruptType;

typedef struct {
    /* Network port debugger is listening on */
    guint16 port;

    /* Main loop running in its own thread */
    GMainContext *mainloop_context;
    GMainLoop *mainloop;

    /* JS state */
    JSRuntime *runtime;
    JSContext *current_context;

    /* The currently connected client, if any */
    GIOChannel *channel;

    GSList *scripts;     /* of GjsDebuggerScripts */
    GSList *breakpoints; /* of GjsDebuggerBreakpoints */

    /* How the two threads communicate on suspending
       and resuming the runtime */
    GMutex *suspend_mutex;
    GCond *suspend_cond;

    /* Protected by suspend mutex */
    gboolean suspended;
    JSScript *suspended_script;
    int suspended_line;
    JSStackFrame *suspended_fp;

    /* General data sharing mutex */
    GMutex *mutex;

    /* Protected by general mutex */
    GjsInterruptType interrupt_type;
    JSScript *interrupt_script;
    int interrupt_line;
    JSStackFrame *interrupt_fp;
    JSStackFrame *interrupt_parent_fp;

    /* Synchronization and error reporting for starting the
       debugger thread */
    GMutex *init_mutex;
    GCond *init_cond;
    GError *init_error;
} GjsDebugger;

typedef struct {
    JSContext *context;
    JSScript *script;
    char *filename;
    int start_line;
    int end_line;
} GjsDebuggerScript;

typedef struct {
    GjsDebuggerScript *script;
    char *filename;
    int line;
} GjsDebuggerBreakpoint;

static void debugger_send_message(GjsDebugger *debugger, const char *format, ...);

static void
debugger_suspend_execution(GjsDebugger *debugger, JSScript *script, int line)
{
    g_mutex_lock(debugger->suspend_mutex);

    gjs_debug_debugger("Suspending execution\n");
    debugger->suspended = TRUE;
    debugger->suspended_script = script;
    debugger->suspended_line = line;
    debugger->suspended_fp = gjs_get_stack_frame(debugger->current_context, 0);

    debugger_send_message(debugger, "stopped %s %d",
                          script->filename, line);

    g_cond_wait(debugger->suspend_cond, debugger->suspend_mutex);

    debugger->suspended = FALSE;
    debugger->suspended_script = NULL;
    debugger->suspended_line = 0;
    debugger->suspended_fp = NULL;
    gjs_debug_debugger("Execution resumed\n");

    g_mutex_unlock(debugger->suspend_mutex);
}

static void
debugger_resume_execution_locked(GjsDebugger *debugger)
{
    gjs_debug_debugger("Resuming execution\n");
    g_cond_broadcast(debugger->suspend_cond);
}

static void
debugger_resume_execution(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->suspend_mutex);
    debugger_resume_execution_locked(debugger);
    g_mutex_unlock(debugger->suspend_mutex);
}

static void
debugger_new_script_handler(JSContext *ctx,
                            const char *filename,
                            uintN line,
                            JSScript *script,
                            JSFunction *func,
                            void *user_data)
{
    GjsDebugger *debugger = user_data;
    GjsDebuggerScript *gjs_script;

    gjs_debug_debugger("New script handler called\n");

    debugger->current_context = ctx;

    gjs_script = g_slice_new0(GjsDebuggerScript);
    gjs_script->context = ctx;
    gjs_script->script = script;
    gjs_script->filename = g_strdup(filename);
    gjs_script->start_line = line;
    gjs_script->end_line = line + JS_GetScriptLineExtent(ctx, script) - 1;

    debugger->scripts = g_slist_prepend(debugger->scripts, gjs_script);
}

static void
debugger_destroy_script_handler(JSContext *ctx,
                                JSScript *script,
                                void *user_data)
{
    GjsDebugger *debugger = user_data;
    GSList *iter;
    GjsDebuggerScript *matching_script = NULL;

    gjs_debug_debugger("Destroy script handler called\n");

    for (iter = debugger->scripts; iter != NULL; iter = iter->next) {
        GjsDebuggerScript *gjs_script = iter->data;

        if (gjs_script->context == ctx && gjs_script->script == script) {
            matching_script = gjs_script;
            debugger->scripts = g_slist_delete_link(debugger->scripts, iter);
            break;
        }
    }

    if (matching_script == NULL)
        return;


    for (iter = debugger->breakpoints; iter != NULL; iter = iter->next) {
        GjsDebuggerBreakpoint *breakpoint = iter->data;

        if (breakpoint->script == matching_script) {
            jsbytecode *pc = JS_LineNumberToPC(matching_script->context,
                                               matching_script->script,
                                               breakpoint->line);
            JS_ClearTrap(matching_script->context,
                         matching_script->script,
                         pc, NULL, NULL);

            breakpoint->script = NULL;
        }
    }

    g_free(matching_script->filename);
    g_slice_free(GjsDebuggerScript, matching_script);
}

static JSTrapStatus
debugger_breakpoint_handler(JSContext *ctx, JSScript *script, jsbytecode *pc,
                            jsval *ret, void *user_data)
{
    GjsDebugger *debugger = user_data;
    int line;

    debugger->current_context = ctx;

    line = JS_PCToLineNumber(ctx, script, pc);
    gjs_debug_debugger("Breakpoint at %s:%d\n", script->filename, line);
    debugger_suspend_execution(debugger, script, line);

    return JSTRAP_CONTINUE;
}

static void
debugger_create_breakpoint(GjsDebugger *debugger, const char *filename, int line)
{
    GjsDebuggerBreakpoint *breakpoint;
    GjsDebuggerScript *matching_script = NULL;
    GSList *iter;

    gjs_debug_debugger("New breakpoint created: %s %d\n", filename, line);

    breakpoint = g_slice_new0(GjsDebuggerBreakpoint);
    breakpoint->filename = g_strdup(filename);
    breakpoint->line = line;

    for (iter = debugger->scripts; iter != NULL; iter = iter->next) {
        GjsDebuggerScript *script = iter->data;

        if (strcmp(script->filename, filename) == 0
            && line >= script->start_line
            && line <= script->end_line) {

            /* Narrower scopes are better */
            if (matching_script == NULL ||
                script->end_line - script->start_line < matching_script->end_line - matching_script->start_line) {
                matching_script = script;
            }
        }
    }

    if (matching_script != NULL) {
        breakpoint->script = matching_script;
        jsbytecode *pc = JS_LineNumberToPC(matching_script->context,
                                           matching_script->script,
                                           line);

        JS_SetTrap(matching_script->context,
                   matching_script->script,
                   pc,
                   debugger_breakpoint_handler,
                   debugger);
    }

    debugger->breakpoints = g_slist_prepend(debugger->breakpoints, breakpoint);
}

static void
debugger_delete_breakpoint(GjsDebugger *debugger, const char *filename, int line)
{
    GSList *iter;

    for (iter = debugger->breakpoints; iter != NULL; iter = iter->next) {
        GjsDebuggerBreakpoint *breakpoint = iter->data;

        if (strcmp(breakpoint->filename, filename) == 0
            && line == breakpoint->line) {

            if (breakpoint->script != NULL) {
                jsbytecode *pc = JS_LineNumberToPC(breakpoint->script->context,
                                                   breakpoint->script->script,
                                                   line);

                JS_ClearTrap(breakpoint->script->context,
                             breakpoint->script->script,
                             pc, NULL, NULL);
            }

            gjs_debug_debugger("Breakpoint deleted: %s %d\n",
                      breakpoint->filename, breakpoint->line);

            g_free(breakpoint->filename);
            g_slice_free(GjsDebuggerBreakpoint, breakpoint);
            debugger->breakpoints = g_slist_delete_link(debugger->breakpoints, iter);

            break;
        }
    }
}

static void
debugger_reset_interrupt_data(GjsDebugger *debugger)
{
    debugger->interrupt_type = INTERRUPT_NONE;
    debugger->interrupt_script = NULL;
    debugger->interrupt_line = 0;
    debugger->interrupt_fp = NULL;
    debugger->interrupt_parent_fp = NULL;
}

static JSTrapStatus
debugger_interrupt_handler(JSContext *ctx, JSScript *script, jsbytecode *pc,
                           jsval *ret, void *user_data)
{
    GjsDebugger *debugger = user_data;

    debugger->current_context = ctx;

    if (debugger->interrupt_type != INTERRUPT_NONE) {
        int line = JS_PCToLineNumber(ctx, script, pc);
        gboolean suspend = TRUE;

        g_mutex_lock(debugger->mutex);

        switch (debugger->interrupt_type) {
        case INTERRUPT_NONE:
            /* Race happened between unlocked check and now.
               Fall through */
            suspend = FALSE;
            break;

        case INTERRUPT_STOP:
            /* Stop was requested; reset the interrupt type */
            debugger_reset_interrupt_data(debugger);
            break;

        case INTERRUPT_STEP:
            if (script == debugger->interrupt_script &&
                line == debugger->interrupt_line) {
                /* Don't stop if we're on the same line */
                suspend = FALSE;
            } else {
                /* Otherwise, we're successfully stepping over.  Reset
                   the type. */
                debugger_reset_interrupt_data(debugger);
            }
            break;

        case INTERRUPT_NEXT:
            if (script == debugger->interrupt_script &&
                line == debugger->interrupt_line) {
                /* Don't stop if we're on the same line */
                suspend = FALSE;
            } else if (gjs_get_stack_frame(ctx, 0) != debugger->interrupt_fp) {
                /* Don't stop if we have a different frame pointer */
                suspend = FALSE;
            } else {
                debugger_reset_interrupt_data(debugger);
            }
            break;

        case INTERRUPT_FINISH:
            if (gjs_get_stack_frame(ctx, 0) != debugger->interrupt_parent_fp) {
                /* Don't stop if we're not in the parent frame pointer */
                suspend = FALSE;
            } else {
                jsval ret;
                const char *value;

                ret = JS_GetFrameReturnValue(ctx, debugger->interrupt_fp);
                value = JS_GetStringBytes(JS_ValueToString(ctx, ret));
                debugger_send_message(debugger, "ret %s", value);

                debugger_reset_interrupt_data(debugger);
            }
        }

        g_mutex_unlock(debugger->mutex);

        if (suspend)
            debugger_suspend_execution(debugger, script, line);
    }

    return JSTRAP_CONTINUE;
}

static void
debugger_suspend_next_iteration(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->mutex);
    g_mutex_lock(debugger->suspend_mutex);
    if (!debugger->suspended)
        debugger->interrupt_type = INTERRUPT_STOP;
    g_mutex_unlock(debugger->suspend_mutex);
    g_mutex_unlock(debugger->mutex);
}

static void
debugger_step(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->mutex);
    g_mutex_lock(debugger->suspend_mutex);
    if (!debugger->suspended) {
        debugger_send_message(debugger, "error execution must be suspended to step");
    } else {
        debugger->interrupt_type = INTERRUPT_STEP;
        debugger->interrupt_script = debugger->suspended_script;
        debugger->interrupt_line = debugger->suspended_line;
        debugger_resume_execution_locked(debugger);
    }
    g_mutex_unlock(debugger->suspend_mutex);
    g_mutex_unlock(debugger->mutex);
}

static void
debugger_next(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->mutex);
    g_mutex_lock(debugger->suspend_mutex);
    if (!debugger->suspended) {
        debugger_send_message(debugger, "error execution must be suspended to step");
    } else {
        debugger->interrupt_type = INTERRUPT_NEXT;
        debugger->interrupt_script = debugger->suspended_script;
        debugger->interrupt_line = debugger->suspended_line;
        debugger->interrupt_fp = gjs_get_stack_frame(debugger->current_context,
                                                     0);
        debugger_resume_execution_locked(debugger);
    }
    g_mutex_unlock(debugger->suspend_mutex);
    g_mutex_unlock(debugger->mutex);
}

static void
debugger_finish(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->mutex);
    g_mutex_lock(debugger->suspend_mutex);
    if (!debugger->suspended) {
        debugger_send_message(debugger, "error execution must be suspended to step");
    } else {
        JSContext *ctx = debugger->current_context;

        debugger->interrupt_type = INTERRUPT_FINISH;
        debugger->interrupt_fp = gjs_get_stack_frame(ctx, 0);
        debugger->interrupt_parent_fp = gjs_get_stack_frame(ctx, 1);
        debugger_resume_execution_locked(debugger);
    }
    g_mutex_unlock(debugger->suspend_mutex);
    g_mutex_unlock(debugger->mutex);
}

static void
debugger_print_stacktrace(GjsDebugger *debugger)
{
    JSStackFrame *fp, *fp_iter = NULL;
    int frame = 0;
    GString *str = g_string_new(NULL);

    while ((fp = JS_FrameIterator(debugger->current_context,
                                  &fp_iter)) != NULL) {
        g_string_append_printf(str, "stack %d ", frame);
        gjs_format_stack_frame(debugger->current_context,
                               fp, str);
        frame++;
    }

    g_string_append(str, "stack end\n");
    debugger_send_message(debugger, str->str);
    g_string_free(str, TRUE);
}

static void
debugger_print_locals(GjsDebugger *debugger, int frame)
{
    JSContext *ctx = debugger->current_context;
    JSObject *obj = NULL;
    JSPropertyDescArray array;

    obj = gjs_get_stack_frame_object(ctx, gjs_get_stack_frame(ctx, frame));

    if (JS_GetPropertyDescArray(ctx, obj, &array)) {
        guint i;

        for (i = 0; i < array.length; i++) {
            const char *name, *type, *value;

            if (!(array.array[i].flags & (JSPD_ARGUMENT | JSPD_VARIABLE)))
                continue;

            name = JS_GetStringBytes(JS_ValueToString(ctx,
                                                      array.array[i].id));
            type = gjs_get_type_name(array.array[i].value);
            value = gjs_value_debug_string(ctx, array.array[i].value);
            debugger_send_message(debugger, "local %s %s %s", name, type, value);
        }
    }
}

static void
debugger_eval(GjsDebugger *debugger, int frame, const char *expression)
{
    JSContext *ctx = debugger->current_context;
    JSStackFrame *fp;
    jsval ret;
    const char *value;

    fp = gjs_get_stack_frame(ctx, frame);

    if (fp != NULL) {
        JS_EvaluateInStackFrame(ctx, fp,
                                expression, strlen(expression),
                                "<debugger>", 0, &ret);
    } else {
        JS_EvaluateScript(ctx, JS_GetGlobalObject(ctx),
                          expression, strlen(expression),
                          "<debugger>", 0, &ret);
    }

    value = JS_GetStringBytes(JS_ValueToString(ctx, ret));
    debugger_send_message(debugger, "ret %s", value);
}

static void
debugger_status(GjsDebugger *debugger)
{
    g_mutex_lock(debugger->suspend_mutex);
    if (debugger->suspended) {
        debugger_send_message(debugger,
                              "stopped %s %d",
                              debugger->suspended_script->filename,
                              debugger->suspended_line);
    } else {
        debugger_send_message(debugger, "running");
    }
    g_mutex_unlock(debugger->suspend_mutex);
}

static void
debugger_send_message(GjsDebugger *debugger, const char *format, ...)
{
    va_list args;
    char *line;
    GIOStatus status;
    gsize bytes_written;

    if (debugger->channel == NULL)
        return;

    va_start(args, format);
    line = g_strdup_vprintf(format, args);
    va_end(args);

    status = g_io_channel_write_chars(debugger->channel,
                                      line, strlen(line),
                                      &bytes_written,
                                      NULL);
    g_free(line);

    if (status != G_IO_STATUS_NORMAL) {
        gjs_debug(GJS_DEBUG_DEBUGGER,
                  "Something went wrong writing data to debugger socket");
    }

    status = g_io_channel_write_chars(debugger->channel,
                                      "\n", 1,
                                      &bytes_written,
                                      NULL);

    if (status != G_IO_STATUS_NORMAL) {
        gjs_debug(GJS_DEBUG_DEBUGGER,
                  "Something went wrong writing data to debugger socket");
    }

    g_io_channel_flush(debugger->channel, NULL);
}

static void
debugger_handle_message(GjsDebugger *debugger, const char *line)
{
    char **args = g_strsplit(line, " ", 0);
    char **i;
    int len;

    for (i = args, len = 0; *i != NULL; i++, len++);

    if (len == 0) {
        debugger_send_message(debugger, "error invalid empty message");
        goto done;
    }

    if (strcmp(args[0], "break") == 0) {
        if (len < 3) {
            debugger_send_message(debugger, "error invalid message \"%s\"", line);
            goto done;
        }

        debugger_create_breakpoint(debugger, args[1], atoi(args[2]));
    } else if (strcmp(args[0], "delete") == 0) {
        if (len < 3) {
            debugger_send_message(debugger, "error invalid message \"%s\"", line);
            goto done;
        }

        debugger_delete_breakpoint(debugger, args[1], atoi(args[2]));
    } else if (strcmp(args[0], "continue") == 0) {
        debugger_resume_execution(debugger);
    } else if (strcmp(args[0], "stop") == 0) {
        debugger_suspend_next_iteration(debugger);
    } else if (strcmp(args[0], "step") == 0) {
        debugger_step(debugger);
    } else if (strcmp(args[0], "next") == 0) {
        debugger_next(debugger);
    } else if (strcmp(args[0], "finish") == 0) {
        debugger_finish(debugger);
    } else if (strcmp(args[0], "stack") == 0) {
        debugger_print_stacktrace(debugger);
    } else if (strcmp(args[0], "locals") == 0) {
        int frame = 0;

        if (len > 1) {
            errno = 0;
            frame = strtol(args[1], NULL, 0);

            if ((frame == 0 && errno != 0) || frame < 0) {
                debugger_send_message(debugger,
                                      "error invalid stack frame \"%s\"",
                                      args[1]);
                goto done;
            }
        }

        debugger_print_locals(debugger, frame);
    } else if (strcmp(args[0], "eval") == 0) {
        int frame = 0;
        char *eval_expr;

        frame = strtol(line + 5, &eval_expr, 0);

        if (frame < 0) {
            debugger_send_message(debugger,
                                  "error invalid stack frame \"%s\"",
                                  args[1]);
            goto done;
        }

        debugger_eval(debugger, frame, eval_expr);
    } else if (strcmp(args[0], "status") == 0) {
        debugger_status(debugger);
    } else {
        debugger_send_message(debugger, "error unknown message \"%s\"", line);
    }

done:
    g_strfreev(args);
}

static gboolean
debugger_client_channel_watch(GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
    GjsDebugger *debugger = user_data;
    char *line;
    gboolean should_close = FALSE;

    if (cond & G_IO_IN) {
        GIOStatus status;
        GError *err = NULL;

        do {
            status = g_io_channel_read_line(channel, &line,
                                            NULL, NULL,
                                            &err);

            if (line != NULL) {
                debugger_handle_message(debugger, g_strstrip(line));
                g_free(line);
            }

            if (err != NULL) {
                gjs_debug(GJS_DEBUG_DEBUGGER,
                          "Got an error reading a line from debugger "
                          "socket: %s",
                          err->message);
                g_error_free(err);
            }
        } while (status == G_IO_STATUS_NORMAL);

        if (status == G_IO_STATUS_ERROR || status == G_IO_STATUS_EOF) {
            should_close = TRUE;
        }
    }

    if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        should_close = TRUE;
    }

    // Returning FALSE will destroy the watch and the channel
    return !should_close;
}

static void
debugger_client_channel_destroy(gpointer user_data)
{
    GjsDebugger *debugger = user_data;
    debugger->channel = NULL;
}

static void
debugger_accept_client_connection(GjsDebugger *debugger, GIOChannel *listen_channel)
{
    int fd;
    GIOChannel *channel;
    GSource *source;

    fd = accept(g_io_channel_unix_get_fd(listen_channel),
                NULL, NULL);

    if (fd < 0) {
        gjs_debug(GJS_DEBUG_DEBUGGER,
                  "Error accepting a new connection on debugger "
                  "socket: %s", strerror(errno));
        return;
    }

    channel = g_io_channel_unix_new(fd);
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

    /* Right now we only allow one client at a time */
    if (debugger->channel != NULL) {
        const char *msg = "already-connected\n";
        gsize bytes_written;
        g_io_channel_write_chars(channel,
                                 msg, strlen(msg),
                                 &bytes_written,
                                 NULL);
        g_io_channel_shutdown(channel, TRUE, NULL);
        g_io_channel_unref(channel);
        return;
    }

    source = g_io_create_watch(channel,
                               G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(source,
                          (GSourceFunc) debugger_client_channel_watch,
                          debugger,
                          debugger_client_channel_destroy);
    g_io_channel_unref(channel);

    g_source_attach(source, g_main_loop_get_context(debugger->mainloop));
    g_source_unref(source);

    debugger->channel = channel;
    debugger_status(debugger);
}

static gboolean
debugger_listen_channel_watch(GIOChannel *listen_channel, GIOCondition cond, gpointer user_data)
{
    GjsDebugger *debugger = user_data;

    if (cond & G_IO_IN) {
        debugger_accept_client_connection(debugger, listen_channel);
    }

    if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        gjs_debug(GJS_DEBUG_DEBUGGER,
                  "Something went terribly wrong with the socket "
                  "listening for debugger connections!  Bailing out.");
        g_main_loop_quit(debugger->mainloop);
        return FALSE;
    }

    return TRUE;
}

static void
debugger_listen(GjsDebugger *debugger)
{
    int fd;
    int reuseaddr = 1;
    struct sockaddr_in addr;
    GIOChannel *channel;
    GSource *source;

    errno = -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        debugger->init_error = g_error_new(GJS_ERROR,
                                           GJS_ERROR_FAILED,
                                           "Error creating socket to "
                                           "listen for debugger "
                                           "connections: %s",
                                           strerror(errno));
        return;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(debugger->port);

    errno = -1;
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        debugger->init_error = g_error_new(GJS_ERROR,
                                           GJS_ERROR_FAILED,
                                           "Unable to bind to debugger "
                                           "socket: %s",
                                           strerror(errno));
        close(fd);
        return;
    }

    errno = -1;
    if (listen(fd, 1) < 0) {
        debugger->init_error = g_error_new(GJS_ERROR,
                                           GJS_ERROR_FAILED,
                                           "Unable to listen to "
                                           "debugger socket: %s",
                                           strerror(errno));
        close(fd);
        return;
    }

    gjs_debug(GJS_DEBUG_DEBUGGER,
              "Listening for debugger connections on port %d",
              debugger->port);

    channel = g_io_channel_unix_new(fd);
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

    source = g_io_create_watch(channel,
                               G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(source,
                          (GSourceFunc) debugger_listen_channel_watch,
                          debugger, NULL);
    g_io_channel_unref(channel);

    g_source_attach(source, g_main_loop_get_context(debugger->mainloop));
    g_source_unref(source);
}

static gpointer
debugger_main(gpointer user_data)
{
    GjsDebugger *debugger = user_data;

    gjs_debug_debugger("Debugger thread running");
    debugger_listen(debugger);

    g_mutex_lock(debugger->init_mutex);
    g_cond_broadcast(debugger->init_cond);
    g_mutex_unlock(debugger->init_mutex);

    g_main_loop_run(debugger->mainloop);

    g_main_loop_unref(debugger->mainloop);
    g_slice_free(GjsDebugger, debugger);

    return NULL;
}

gboolean
gjs_debugger_init(JSRuntime *runtime, guint16 port, GError **err)
{
    GjsDebugger *debugger = g_slice_new0(GjsDebugger);
    GMainContext *mainloop_context = g_main_context_new();
    GThread *thread;

    gjs_debug_debugger("Starting debugger thread");

    JS_SetNewScriptHook(runtime, debugger_new_script_handler, debugger);
    JS_SetDestroyScriptHook(runtime, debugger_destroy_script_handler, debugger);
    JS_SetDebuggerHandler(runtime, debugger_breakpoint_handler, debugger);
    JS_SetInterrupt(runtime, debugger_interrupt_handler, debugger);

    debugger->port = port;
    debugger->runtime = runtime;
    debugger->mainloop = g_main_loop_new(mainloop_context, FALSE);
    debugger->mutex = g_mutex_new();
    debugger->suspend_mutex = g_mutex_new();
    debugger->suspend_cond = g_cond_new();
    debugger->init_mutex = g_mutex_new();
    debugger->init_cond = g_cond_new();

    thread = g_thread_create(debugger_main, debugger, TRUE, err);

    g_main_context_unref(mainloop_context);

    g_mutex_lock(debugger->init_mutex);
    g_cond_wait(debugger->init_cond, debugger->init_mutex);

    if (debugger->init_error != NULL)
        g_propagate_error(err, debugger->init_error);

    g_mutex_unlock(debugger->init_mutex);

    return (*err == NULL);
}

