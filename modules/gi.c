/* -*- mode: C; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/*
 * Copyright (c) 2008  litl, LLC
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

#include "gi.h"

#include <util/misc.h>

#include <string.h>

#include "gjs/native.h"
#include "gjs/compat.h"
#include "gi/repo.h"

JSBool
gjs_define_gi_stuff(JSContext      *context,
                    JSObject       *module_obj)
{
    return gjs_define_repo(context, module_obj, "gi");
}

/* GJS_NATIVE_SUPPLIES_MODULE_OBJ means we will define "gi" instead
 * of defining the stuff inside "gi" only.
 */
GJS_REGISTER_NATIVE_MODULE_WITH_FLAGS("gi",
                                      gjs_define_gi_stuff,
                                      GJS_NATIVE_SUPPLIES_MODULE_OBJ)
