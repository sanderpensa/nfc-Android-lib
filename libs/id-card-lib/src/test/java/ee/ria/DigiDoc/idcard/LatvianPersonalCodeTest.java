package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;

/**
 * The Latvian personal-code → DOB mapping is the one piece of LV-specific
 * derivation that has no test on real cards (DOB comes from the code itself,
 * not from any EF). Lock its semantics down here.
 */
public final class LatvianPersonalCodeTest {

    @Test
    public void parseDateOfBirth_oldFormat_century19xx() {
        // Old format: DDMMYY-CZZZQ, century digit 1 → 19xx
        LocalDate dob = LatvianPersonalCode.parseDateOfBirth("150385-12345");
        assertThat(dob).isEqualTo(LocalDate.of(1985, 3, 15));
    }

    @Test
    public void parseDateOfBirth_oldFormat_century20xx() {
        LocalDate dob = LatvianPersonalCode.parseDateOfBirth("010100-21234");
        assertThat(dob).isEqualTo(LocalDate.of(2000, 1, 1));
    }

    @Test
    public void parseDateOfBirth_oldFormat_century18xx() {
        LocalDate dob = LatvianPersonalCode.parseDateOfBirth("310199-01234");
        assertThat(dob).isEqualTo(LocalDate.of(1899, 1, 31));
    }

    @Test
    public void parseDateOfBirth_withoutDash_alsoParses() {
        // The parser strips dashes before slicing.
        LocalDate dob = LatvianPersonalCode.parseDateOfBirth("15038512345");
        assertThat(dob).isEqualTo(LocalDate.of(1985, 3, 15));
    }

    @Test
    public void parseDateOfBirth_newFormat_returnsNull() {
        // PMLP spec: 1st digit "3", 2nd digit "2"-"9". DOB not encoded.
        assertThat(LatvianPersonalCode.parseDateOfBirth("321234-56789")).isNull();
        assertThat(LatvianPersonalCode.parseDateOfBirth("32123456789")).isNull();
        // Whole 3[2-9] range is reserved for the updated format.
        assertThat(LatvianPersonalCode.parseDateOfBirth("331234-56789")).isNull();
        assertThat(LatvianPersonalCode.parseDateOfBirth("391234-56789")).isNull();
        // Demo-card code observed in the field also resolves to null (no DOB encoded).
        assertThat(LatvianPersonalCode.parseDateOfBirth("326305-17052")).isNull();
    }

    @Test
    public void parseDateOfBirth_unparseablePrefix_returnsNull() {
        // 4X-9X aren't valid old-format days (DD<=31) and aren't updated-format
        // prefixes (PMLP reserves 3[2-9]) — legacy parser fails, surfaces as null.
        assertThat(LatvianPersonalCode.parseDateOfBirth("411234-56789")).isNull();
        assertThat(LatvianPersonalCode.parseDateOfBirth("991234-56789")).isNull();
    }

    @Test
    public void parseDateOfBirth_nullOrEmpty_returnsNull() {
        assertThat(LatvianPersonalCode.parseDateOfBirth(null)).isNull();
        assertThat(LatvianPersonalCode.parseDateOfBirth("")).isNull();
    }

    @Test
    public void parseDateOfBirth_tooShort_returnsNull() {
        assertThat(LatvianPersonalCode.parseDateOfBirth("12345")).isNull();
    }

    @Test
    public void parseDateOfBirth_invalidMonth_returnsNull() {
        // Month 13 — LocalDate.of throws, parser catches and returns null.
        assertThat(LatvianPersonalCode.parseDateOfBirth("011385-12345")).isNull();
    }

    @Test
    public void parseDateOfBirth_invalidCenturyDigit_returnsNull() {
        // Century digit 5 → not in {0, 1, 2} → parser throws internally → null.
        assertThat(LatvianPersonalCode.parseDateOfBirth("010100-51234")).isNull();
    }
}
