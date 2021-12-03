/*
 * Copyright (c) 2020 NVIDIA CORPORATION.  All rights reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

#include <ctype.h>

int strcasecmp(const char *s1, const char *s2)
{
    int ret, i1, i2;
    do {
        i1 = toupper(*s1++);
        i2 = toupper(*s2++);
        ret = (i1 > i2) - (i1 < i2);
    } while ((!ret) && (i1 != '\0') && (i2 != '\0'));
    return ret;
}

