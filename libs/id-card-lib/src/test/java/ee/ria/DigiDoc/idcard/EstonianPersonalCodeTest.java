package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;

/**
 * The Estonian personal-code → date-of-birth mapping. Its Latvian counterpart is
 * covered by {@link LatvianPersonalCodeTest}; both answer null rather than throwing,
 * and this pins that for the Estonian format.
 */
public final class EstonianPersonalCodeTest {

    @Test
    public void parseDateOfBirth_centuryDigitSelectsTheCentury() {
        // The captured Estonian test card's code; the replay test asserts the same date.
        assertThat(EstonianPersonalCode.parseDateOfBirth("38001085718"))
                .isEqualTo(LocalDate.of(1980, 1, 8));
        assertThat(EstonianPersonalCode.parseDateOfBirth("10001085718"))
                .isEqualTo(LocalDate.of(1800, 1, 8));
        assertThat(EstonianPersonalCode.parseDateOfBirth("50001085718"))
                .isEqualTo(LocalDate.of(2000, 1, 8));
        assertThat(EstonianPersonalCode.parseDateOfBirth("70001085718"))
                .isEqualTo(LocalDate.of(2100, 1, 8));
    }

    /** A leading digit outside 1-8 names no century, so there is no date to give. */
    @Test
    public void parseDateOfBirth_centuryDigitOutsideTheRange_returnsNull() {
        assertThat(EstonianPersonalCode.parseDateOfBirth("98001085718")).isNull();
        assertThat(EstonianPersonalCode.parseDateOfBirth("08001085718")).isNull();
    }

    /** Month 13 is rejected, not rolled into January of the next year. */
    @Test
    public void parseDateOfBirth_impossibleDate_returnsNull() {
        assertThat(EstonianPersonalCode.parseDateOfBirth("38013085718")).isNull();
        assertThat(EstonianPersonalCode.parseDateOfBirth("38001325718")).isNull();
    }

    @Test
    public void parseDateOfBirth_nonNumeric_returnsNull() {
        assertThat(EstonianPersonalCode.parseDateOfBirth("3AB01085718")).isNull();
    }

    @Test
    public void parseDateOfBirth_tooShort_returnsNull() {
        assertThat(EstonianPersonalCode.parseDateOfBirth("380108")).isNull();
        assertThat(EstonianPersonalCode.parseDateOfBirth("")).isNull();
    }

    @Test
    public void parseDateOfBirth_null_returnsNull() {
        assertThat(EstonianPersonalCode.parseDateOfBirth(null)).isNull();
    }
}
