/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <stdio.h>

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
	/* UUID :{74d61413-c198-4beb-8b74-680157b32b4d} */
	{ 0x74d61413, 0xc198, 0x4beb,
	  {0x8b, 0x74, 0x68, 0x01, 0x57, 0xb3, 0x2b, 0x4d} },

	/* optional configuration options here */
	{
		/* four pages for heap */
		TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4096),
	},
};
