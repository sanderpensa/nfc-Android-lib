/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package ee.ria.DigiDoc.smartcardreader.nfc.example.util

import android.widget.EditText

/**
 * The codes the card accepts, with the lengths it accepts them in
 * (IDEMIA_LV.md §7; the CAN is the six-digit number printed on the card).
 */
enum class CodeField(val label: String, val min: Int, val max: Int) {
    CAN("CAN", 6, 6),
    PIN1("PIN1", 4, 12),
    PIN2("PIN2", 5, 12),
    PUK("PUK", 8, 12),
}

/**
 * The field's contents, or `null` if they cannot be a valid code — in which
 * case an inline error is shown on the field and focus moved to it, so the
 * caller should simply return.
 *
 * Checking here matters more than it looks. An unchecked empty field
 * reaches `Idemia.code()`, which pads whatever it is given to twelve
 * bytes with `0xFF` — so an empty box is presented to the card as a
 * PIN of twelve `0xFF` bytes. The card compares it, rejects it, and
 * decrements the retry counter against a value the user never typed. On the
 * unblock screen the same input *sets* the new code, so an empty box can
 * leave the card holding a PIN that no keypad entry can ever reproduce,
 * which looks exactly like "unblocking did not help".
 */
fun EditText.readCode(field: CodeField): String? {
    val value = text.toString()
    val problem = when {
        value.isEmpty() -> "Enter your ${field.label}"
        value.length < field.min || value.length > field.max ->
            if (field.min == field.max) {
                "${field.label} is ${field.min} digits"
            } else {
                "${field.label} is ${field.min}-${field.max} digits"
            }
        !value.all { it.isDigit() } -> "${field.label} is digits only"
        else -> null
    }
    if (problem != null) {
        error = problem
        requestFocus()
        return null
    }
    error = null
    return value
}
