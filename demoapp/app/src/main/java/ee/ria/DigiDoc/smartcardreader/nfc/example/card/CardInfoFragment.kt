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

package ee.ria.DigiDoc.smartcardreader.nfc.example.card

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.fragment.app.activityViewModels
import androidx.navigation.fragment.findNavController
import ee.ria.DigiDoc.smartcardreader.nfc.example.R
import ee.ria.DigiDoc.smartcardreader.nfc.example.databinding.FragmentCardInfoBinding
import ee.ria.DigiDoc.smartcardreader.nfc.example.viewmodel.DataViewModel

class CardInfoFragment : Fragment() {

    private val dataViewModel: DataViewModel by activityViewModels()
    private lateinit var binding: FragmentCardInfoBinding
    private lateinit var givenNameTextView: TextView
    private lateinit var surnameTextView: TextView
    private lateinit var personalCodeTextView: TextView
    private lateinit var dateOfBirthTextView: TextView
    private lateinit var documentNumberTextView: TextView
    private lateinit var citizenshipTextView: TextView
    private lateinit var dateOfExpiryTextView: TextView
    private lateinit var certExpiryTextView: TextView
    private lateinit var cardTypeTextView: TextView
    private lateinit var pin1TextView: TextView
    private lateinit var pin2TextView: TextView

    private lateinit var closeButton: Button

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentCardInfoBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        givenNameTextView = binding.textViewFirstName
        surnameTextView = binding.textViewLastName
        personalCodeTextView = binding.textViewPersonalCode
        dateOfBirthTextView = binding.textViewDateOfBirth
        documentNumberTextView = binding.textViewDocumentNumber
        citizenshipTextView = binding.textViewCitizenship
        dateOfExpiryTextView = binding.textViewExpirationDate
        certExpiryTextView = binding.textViewCertExpiry
        cardTypeTextView = binding.textViewCardType
        pin1TextView = binding.textViewPin1
        pin2TextView = binding.textViewPin2

        closeButton = binding.buttonClose

        closeButton.setOnClickListener {
            findNavController().popBackStack(R.id.homeFragment, false)
        }
        displayCardInfo()

        requireActivity().onBackPressedDispatcher.addCallback(requireActivity(), object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                findNavController().popBackStack(R.id.homeFragment, false)
            }
        })
    }

    private fun displayCardInfo() {
        givenNameTextView.text = getString(R.string.first_name, dataViewModel.getGivenNames())
        surnameTextView.text = getString(R.string.last_name, dataViewModel.getSurname())
        personalCodeTextView.text =
            getString(R.string.personal_code, dataViewModel.getPersonalCode())
        dateOfBirthTextView.text =
            getString(R.string.date_of_birth, dataViewModel.getDateOfBirth() ?: "-")
        documentNumberTextView.text =
            getString(R.string.document_number, dataViewModel.getDocumentNumber())
        // Each row shows what its own source states, or a dash. The two expiries are
        // separate rows because they are separate facts from separate places: the
        // document's date comes from the card's personal-data file, the certificate's
        // from the certificate. A Latvian card has only the second; an Estonian one
        // only the first.
        citizenshipTextView.text = getString(
            R.string.citizenship, dataViewModel.getCitizenship() ?: "-")
        dateOfExpiryTextView.text = getString(
            R.string.document_expiry, dataViewModel.getDocumentExpiryDate() ?: "-")
        certExpiryTextView.text = getString(
            R.string.cert_expiry, dataViewModel.getCertExpiryDate() ?: "-")
        cardTypeTextView.text = getString(R.string.card_type, dataViewModel.getCardType())

        pin1TextView.text = getString(R.string.pin1_counter, dataViewModel.getPin1Counter())
        pin2TextView.text = getString(R.string.pin2_counter, dataViewModel.getPin2Counter())
    }
}