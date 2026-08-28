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

package ee.ria.DigiDoc.idcard;

import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;

import java.time.LocalDate;

/**
 * Personal data file contents.
 *
 * <p><b>What the card's own personal-data files state, and nothing else.</b> A field
 * belongs here because at least one card model reads it from a file; a model that
 * does not state it answers {@code null}. Certificate facts — the subject's country,
 * a validity window — are not personal data and are not here: a caller wanting them
 * has the certificate, from {@link Token#certificate}.
 *
 * <p>One exception, called out where it happens: Latvian cards fill
 * {@code surname}, {@code givenNames} and {@code documentNumber} from their
 * authentication certificate, because those are fields other models do state and the
 * LV card states them nowhere else. See {@code LatvianPersonalDataParser}.
 */
@AutoValue
public abstract class PersonalData {

    public abstract String surname();

    public abstract String givenNames();

    /**
     * Cardholder's citizenship.
     *
     * <p>Null rather than an empty string where a card does not state it: "did not
     * say" and "said nothing" are different answers, and only the first is true.
     */
    @Nullable public abstract String citizenship();

    @Nullable public abstract LocalDate dateOfBirth();

    public abstract String personalCode();

    public abstract String documentNumber();

    /**
     * Expiry date of the physical document, as printed on the card.
     *
     * <p>Not a certificate's validity window — a card can outlive its certificates,
     * and the two answer different questions.
     */
    @Nullable public abstract LocalDate documentExpiryDate();

    public abstract CardType cardType();

    static PersonalData create(String surname, String givenNames,
                               @Nullable String citizenship, @Nullable LocalDate dateOfBirth,
                               String personalCode, String documentNumber,
                               @Nullable LocalDate documentExpiryDate, CardType cardType) {
        return new AutoValue_PersonalData(surname, givenNames, citizenship,
                dateOfBirth, personalCode, documentNumber, documentExpiryDate, cardType);
    }
}
