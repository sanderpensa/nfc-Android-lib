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

package ee.ria.DigiDoc.smartcardreader.nfc.example.viewmodel

import androidx.lifecycle.ViewModel
import ee.ria.DigiDoc.idcard.PersonalData

class DataViewModel : ViewModel() {
    private var can: String = ""
    private var givenNames: String = ""
    private var surname: String = ""
    private var personalCode: String = ""
    private var citizenship: String? = null
    private var dateOfBirth: String? = null
    private var documentNumber: String = ""
    private var documentExpiryDate: String? = null

    /**
     * Derived from the authentication certificate, not from [PersonalData].
     *
     * The library reports what the card's personal-data files state; a certificate's
     * validity is a fact about the certificate. An integrator wanting it does what
     * this app does — reads the certificate it already has and looks. Worth showing
     * because on a Latvian card it is the only expiry there is.
     */
    private var certExpiryDate: String? = null
    private var cardType: String = ""
    private var containerName: String = ""

    private var pin1Counter: Int = 0
    private var pin2Counter: Int = 0

    fun setContainerName(containerName: String) {
        this.containerName = containerName
    }

    fun getContainerName(): String {
        return this.containerName
    }

    fun setCan(can: String) {
        this.can = can
    }

    fun clearCan() {
        this.can = ""
    }

    /**
     * Replaces every card fact held here. This model is scoped to the activity, so it
     * outlives the fragment and survives one tap to the next — a field this does not
     * overwrite is a field showing the previous card's value.
     *
     * [certExpiryDate] does not come from [PersonalData], so it is cleared here and
     * set separately by whoever read the certificate.
     */
    fun setUserValues(cardData: PersonalData) {
        this.givenNames = cardData.givenNames()
        this.surname = cardData.surname()
        this.personalCode = cardData.personalCode()
        this.citizenship = cardData.citizenship()
        this.dateOfBirth = cardData.dateOfBirth()?.toString()
        this.documentNumber = cardData.documentNumber()
        this.documentExpiryDate = cardData.documentExpiryDate()?.toString()
        this.certExpiryDate = null
        this.cardType = cardData.cardType().name
    }

    fun getCan(): String {
        return can
    }

    fun getGivenNames(): String {
        return givenNames
    }

    fun getSurname(): String {
        return surname
    }

    fun getPersonalCode(): String {
        return personalCode
    }

    fun getCitizenship(): String? {
        return citizenship
    }

    fun getDateOfBirth(): String? {
        return dateOfBirth
    }

    fun getDocumentNumber(): String {
        return documentNumber
    }

    fun getDocumentExpiryDate(): String? {
        return documentExpiryDate
    }

    fun setCertExpiryDate(certExpiryDate: String?) {
        this.certExpiryDate = certExpiryDate
    }

    fun getCertExpiryDate(): String? {
        return certExpiryDate
    }

    fun getCardType(): String {
        return cardType
    }

    fun setPin1Counter(p1: Int) {
        pin1Counter = p1
    }

    fun setPin2Counter(p2: Int) {
        pin2Counter = p2
    }

    fun getPin1Counter(): Int {
        return pin1Counter
    }

    fun getPin2Counter(): Int {
        return pin2Counter
    }

}