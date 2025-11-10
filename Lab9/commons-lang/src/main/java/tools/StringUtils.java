/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package tools;

//@Immutable
public class StringUtils {

    /**
     * Capitalizes a String changing the first character to title case as per
     * {@link Character#toTitleCase(int)}. No other characters are changed.
     *
     * <p>
     * For a word based algorithm, see
     * {@link org.apache.commons.text.WordUtils#capitalize(String)}. A {@code null}
     * input String returns {@code null}.
     * </p>
     *
     * @param str the String to capitalize, may be null.
     * @return the capitalized String, {@code null} if null String input.
     * @see org.apache.commons.text.WordUtils#capitalize(String)
     * @see #uncapitalize(String)
     * @since 2.0
     */
    public static String capitalize(final String str) {
        if (isEmpty(str)) {
            return str;
        }
        final int firstCodepoint = str.codePointAt(0);
        final int newCodePoint = Character.toTitleCase(firstCodepoint);
        if (firstCodepoint == newCodePoint) {
            // already capitalized
            return str;
        }
        final int[] newCodePoints = str.codePoints().toArray();
        newCodePoints[0] = newCodePoint; // copy the first code point
        return new String(newCodePoints, 0, newCodePoints.length);
    }

    /**
     * Swaps the case of a String changing upper and title case to lower case, and
     * lower case to upper case.
     *
     * <ul>
     * <li>Upper case character converts to Lower case</li>
     * <li>Title case character converts to Lower case</li>
     * <li>Lower case character converts to Upper case</li>
     * </ul>
     *
     * <p>
     * For a word based algorithm, see
     * {@link org.apache.commons.text.WordUtils#swapCase(String)}. A {@code null}
     * input String returns {@code null}.
     * </p>
     * <p>
     * NOTE: This method changed in Lang version 2.0. It no longer performs a word
     * based algorithm. If you only use ASCII, you will notice no change. That
     * functionality is available in org.apache.commons.lang3.text.WordUtils.
     * </p>
     *
     * @param str the String to swap case, may be null.
     * @return the changed String, {@code null} if null String input.
     */
    public static String swapCase(final String str) {
        if (isEmpty(str)) {
            return str;
        }
        final int strLen = str.length();
        final int[] newCodePoints = new int[strLen]; // cannot be longer than the char array
        int outOffset = 0;
        for (int i = 0; i < strLen;) {
            final int oldCodepoint = str.codePointAt(i);
            final int newCodePoint;
            if (Character.isUpperCase(oldCodepoint) || Character.isTitleCase(oldCodepoint)) {
                newCodePoint = Character.toLowerCase(oldCodepoint);
            } else if (Character.isLowerCase(oldCodepoint)) {
                newCodePoint = Character.toUpperCase(oldCodepoint);
            } else {
                newCodePoint = oldCodepoint;
            }
            newCodePoints[outOffset++] = newCodePoint;
            i += Character.charCount(newCodePoint);
        }
        return new String(newCodePoints, 0, outOffset);
    }

    /**
     * Tests if a CharSequence is empty ("") or null.
     *
     * <pre>
     * StringUtils.isEmpty(null)      = true
     * StringUtils.isEmpty("")        = true
     * StringUtils.isEmpty(" ")       = false
     * StringUtils.isEmpty("bob")     = false
     * StringUtils.isEmpty("  bob  ") = false
     * </pre>
     *
     * <p>
     * NOTE: This method changed in Lang version 2.0. It no longer trims the
     * CharSequence. That functionality is available in isBlank().
     * </p>
     *
     * @param cs the CharSequence to check, may be null.
     * @return {@code true} if the CharSequence is empty or null.
     * @since 3.0 Changed signature from isEmpty(String) to isEmpty(CharSequence)
     */
    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }
}
