//
//  monero_transfer_utils.cpp
//  Copyright © 2018 MyMonero. All rights reserved.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are
//  permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of
//	conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list
//	of conditions and the following disclaimer in the documentation and/or other
//	materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be
//	used to endorse or promote products derived from this software without specific
//	prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
//  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//
//
#include "monero_transfer_utils.hpp"
#include "wallet_errors.h"
#include "string_tools.h"
#include "monero_paymentID_utils.hpp"
#include "monero_key_image_utils.hpp"
#include "offshore/asset_types.h"
//
using namespace std;
using namespace crypto;
using namespace std;
using namespace boost;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
using namespace monero_fee_utils;
using namespace monero_key_image_utils; // for API response parsing
//
// Transfer parsing/derived properties
bool monero_transfer_utils::is_transfer_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() / m_local_bc_height */
	network_type nettype
) {
	if(!is_tx_spendtime_unlocked(unlock_time, block_height, blockchain_size, nettype))
		return false;

	if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > blockchain_size)
		return false;

	return true;
}
bool monero_transfer_utils::is_tx_spendtime_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size,
	network_type nettype
) {
	if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
	{
		//interpret as block index
		if(blockchain_size-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
			return true;
		else
			return false;
	}else
	{
		//interpret as time
		uint64_t current_time = static_cast<uint64_t>(time(NULL));
		// XXX: this needs to be fast, so we'd need to get the starting heights
		// from the daemon to be correct once voting kicks in
		uint64_t v2height = nettype == TESTNET ? 624634 : nettype == STAGENET ? (uint64_t)-1/*TODO*/ : 1009827;
		uint64_t leeway = block_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
		if(current_time + leeway >= unlock_time)
			return true;
		else
			return false;
	}
	return false;
}
//
namespace {
CreateTransactionErrorCode _add_pid_to_tx_extra(
	const optional<string>& payment_id_string,
	vector<uint8_t> &extra
) { // Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
	bool r = false;
	if (payment_id_string != none && payment_id_string->size() > 0) {
		crypto::hash payment_id;
		r = monero_paymentID_utils::parse_long_payment_id(*payment_id_string, payment_id);
		if (r) {
			std::string extra_nonce;
			cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
			r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			if (!r) {
				return couldntAddPIDNonceToTXExtra;
			}
		} else {
			crypto::hash8 payment_id8;
			r = monero_paymentID_utils::parse_short_payment_id(*payment_id_string, payment_id8);
			if (!r) { // a PID has been specified by the user but the last resort in validating it fails; error
				return invalidPID;
			}
			std::string extra_nonce;
			cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
			r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			if (!r) {
				return couldntAddPIDNonceToTXExtra;
			}
		}
	}
	return noError;
}
bool _rct_hex_to_rct_commit(
	const std::string &rct_string,
	rct::key &rct_commit
) {
	// rct string is empty if output is non RCT
	if (rct_string.empty()) {
		return false;
	}
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	std::string rct_commit_str = rct_string.substr(0,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
	string_tools::hex_to_pod(rct_commit_str, rct_commit);
	return true;
}
bool _rct_hex_to_decrypted_mask(
	const std::string &rct_string,
	const crypto::secret_key &view_secret_key,
	const crypto::public_key& tx_pub_key,
	uint64_t internal_output_index,
	rct::key &decrypted_mask
) {
	// rct string is empty if output is non RCT
	if (rct_string.empty()) {
		return false;
	}
	// rct_string is a magic value if output is RCT and coinbase
	if (rct_string == "coinbase") {
		decrypted_mask = rct::identity();
		return true;
	}
	auto make_key_derivation = [&]() {
		crypto::key_derivation derivation;
		bool r = generate_key_derivation(tx_pub_key, view_secret_key, derivation);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
		crypto::secret_key scalar;
		crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
		return rct::sk2rct(scalar);
	};
	rct::key encrypted_mask;
	// rct_string is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
	if (rct_string.size() < 64 * 2) {
		decrypted_mask = rct::genCommitmentMask(make_key_derivation());
		return true;
	}
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	std::string encrypted_mask_str = rct_string.substr(64,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
	string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
	//
	if (encrypted_mask == rct::identity()) {
		// backward compatibility; should no longer be needed after v11 mainnet fork
		decrypted_mask = encrypted_mask;
		return true;
	}
	//
	// Decrypt the mask
	sc_sub(decrypted_mask.bytes,
		encrypted_mask.bytes,
		rct::hash_to_scalar(make_key_derivation()).bytes);
	
	return true;
}
bool _verify_sec_key(const crypto::secret_key &secret_key, const crypto::public_key &public_key)
{ // borrowed from device_default.cpp
	crypto::public_key calculated_pub;
	bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
	return r && public_key == calculated_pub;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_xasset_amount(const uint64_t xusd_amount, const std::string asset_type, offshore::pricing_record pr)
{ // borrowed from wallet2.cpp
	boost::multiprecision::uint128_t xusd_128 = xusd_amount;
	boost::multiprecision::uint128_t exchange_128 =
		asset_type == "XAG" ? pr.xAG :
		asset_type == "XAU" ? pr.xAU :
		asset_type == "XAUD" ? pr.xAUD :
		asset_type == "XBTC" ? pr.xBTC :
		asset_type == "XCAD" ? pr.xCAD :
		asset_type == "XCHF" ? pr.xCHF :
		asset_type == "XCNY" ? pr.xCNY :
		asset_type == "XEUR" ? pr.xEUR :
		asset_type == "XGBP" ? pr.xGBP :
		asset_type == "XJPY" ? pr.xJPY :
		asset_type == "XNOK" ? pr.xNOK :
		asset_type == "XNZD" ? pr.xNZD :
		asset_type == "XUSD" ? pr.xUSD :
		pr.unused1;
	boost::multiprecision::uint128_t xasset_128 = xusd_128 * exchange_128;
	xasset_128 /= 1000000000000;
	return (uint64_t)xasset_128;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_xusd_amount(const uint64_t amount, const std::string asset_type, offshore::pricing_record pr)
{ // borrowed from wallet2.cpp
	boost::multiprecision::uint128_t amount_128 = amount;
	boost::multiprecision::uint128_t exchange_128 =
		asset_type == "XAG" ? pr.xAG :
		asset_type == "XAU" ? pr.xAU :
		asset_type == "XAUD" ? pr.xAUD :
		asset_type == "XBTC" ? pr.xBTC :
		asset_type == "XCAD" ? pr.xCAD :
		asset_type == "XCHF" ? pr.xCHF :
		asset_type == "XCNY" ? pr.xCNY :
		asset_type == "XEUR" ? pr.xEUR :
		asset_type == "XGBP" ? pr.xGBP :
		asset_type == "XJPY" ? pr.xJPY :
		asset_type == "XNOK" ? pr.xNOK :
		asset_type == "XNZD" ? pr.xNZD :
		asset_type == "XHV" ? pr.unused1 :
		pr.unused1;
    if (asset_type == "XHV") {
      boost::multiprecision::uint128_t xusd_128 = amount_128 * exchange_128;
      xusd_128 /= 1000000000000;
      return (uint64_t)xusd_128;
    } else {
      boost::multiprecision::uint128_t xusd_128 = amount_128 * 1000000000000;
      xusd_128 /= exchange_128;
      return (uint64_t)xusd_128;
    }
}
//----------------------------------------------------------------------------------------------------
uint64_t get_offshore_fee(uint64_t amount, uint32_t priority)
{ // borrowed from wallet2.cpp
	uint64_t fee_estimate = amount;
	switch(priority) {
		case 4:
			fee_estimate /= 5; // 20% - "workday rush"
			break;
		case 3:
			fee_estimate /= 10; // 10% "1-day rush"
			break;
		case 2:
			fee_estimate /= 20; // 5% - "premium mint"
			break;
		default:
			fee_estimate /= 500; // 0.2% - "standard mint"
			break;
	}

	// Return the fee
	return fee_estimate;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_onshore_fee(uint64_t amount, uint32_t priority)
{
	uint64_t fee_estimate = amount;
	switch(priority) {
		case 4:
			fee_estimate /= 5; // 20% - "workday rush"
			break;
		case 3:
			fee_estimate /= 10; // 10% "1-day rush"
			break;
		case 2:
			fee_estimate /= 20; // 5% - "premium mint"
			break;
		default:
			fee_estimate /= 500; // 0.2% - "standard mint"
			break;
	}

	// Return the fee
	return fee_estimate;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_offshore_to_offshore_fee(uint64_t amount, uint32_t priority)
{
  return 0;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_xasset_to_xusd_fee(uint64_t amount, uint32_t priority, use_fork_rules_fn_type use_fork_rules_fn)
{
  if (use_fork_rules_fn(HF_VERSION_XASSET_FEES_V2, 0)) {
    return (amount * 5) / 1000;
  }

  return 0;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_xasset_transfer_fee(uint64_t amount, uint32_t priority)
{
  return 0;
}
//----------------------------------------------------------------------------------------------------
uint64_t get_xusd_to_xasset_fee(uint64_t amount, uint32_t priority, use_fork_rules_fn_type use_fork_rules_fn)
{
  if (use_fork_rules_fn(HF_VERSION_XASSET_FEES_V2, 0)) {
    return (amount * 5) / 1000;
  }

  return 0;
}
//----------------------------------------------------------------------------------------------------
uint64_t convert_base_fee_to_source_asset_type(const uint64_t base_fee_orig, string from_asset_type, string to_asset_type, offshore::pricing_record pr)
{
	uint64_t base_fee = base_fee_orig;

	// copied from wallet2.cpp:
	// Convert fees to source asset type equvelent value if only it is a conversion.
	// the reason we do this is we need the pr record for conversions.
	// but we still want assets to be transferable even in the absence of oracle.
	// so we don't try to adjust the fee according to usd equivalent.
	// the only donwnside is fees are little bit higher for the assets that has high usd value.
 	if (from_asset_type == "XHV") {
 	} else if (from_asset_type == "XUSD") {
		if (from_asset_type != to_asset_type) {
			base_fee = get_xusd_amount(base_fee_orig, "XHV", pr);
		}
 	} else {
   		if (from_asset_type != to_asset_type) {
     		// Convert fee to xAsset
			base_fee = get_xasset_amount(get_xusd_amount(base_fee_orig, "XHV", pr), from_asset_type, pr);
	    }
	}

	return base_fee;
}
} // unnamed namespace
//
namespace
{
	template<typename T>
	T pop_index(std::vector<T>& vec, size_t idx)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

		T res = std::move(vec[idx]);
		if (idx + 1 != vec.size()) {
			vec[idx] = std::move(vec.back());
		}
		vec.resize(vec.size() - 1);
		
		return res;
	}
	//
	template<typename T>
	T pop_random_value(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		size_t idx = crypto::rand<size_t>() % vec.size();
		return pop_index (vec, idx);
	}
}
//
//
//
// Decomposed Send procedure
void monero_transfer_utils::send_step1__prepare_params_for_get_decoys(
	Send_Step1_RetVals &retVals,
	//
	const string &from_asset_type,
	const string &to_asset_type,
	const optional<string>& payment_id_string,
	uint64_t sending_amount,
	bool is_sweeping,
	uint32_t simple_priority,
	offshore::pricing_record pr,
	use_fork_rules_fn_type use_fork_rules_fn,
	//
	const vector<SpendableOutput> &unspent_outs,
	uint64_t fee_per_b, // per v8
	uint64_t fee_quantization_mask,
	//
	optional<uint64_t> passedIn_attemptAt_fee
) {
	retVals = {};
	//
	if (is_sweeping) {
		if (sending_amount != 0 && sending_amount != UINT64_MAX) {
			THROW_WALLET_EXCEPTION_IF(
				sending_amount != 0 && sending_amount != UINT64_MAX,
				error::wallet_internal_error, "Ambiguous arguments; Pass sending_amount 0 while sweeping"
			);
			return;
		}
	} else { // not sweeping
		if (sending_amount == 0) {
			retVals.errCode = enteredAmountTooLow;
			return;
		}
	}
	//
	uint32_t fake_outs_count = monero_fork_rules::fixed_mixinsize();
	retVals.mixin = fake_outs_count;
	//
	bool use_rct = true;
	bool bulletproof = true;
	bool clsag = true;
	//
	std::vector<uint8_t> extra;
	CreateTransactionErrorCode tx_extra__code = _add_pid_to_tx_extra(payment_id_string, extra);
	if (tx_extra__code != noError) {
		retVals.errCode = tx_extra__code;
		return;
	}
	
	// determine if transaction is offshore and if so what type
	bool offshore = false;
	bool onshore = false;
	bool offshore_transfer = false;
	bool xasset_transfer = false;
	bool xasset_to_xusd = false;
	bool xusd_to_xasset = false;
    if (from_asset_type != "XHV" || to_asset_type != "XHV") {
		// Populate the txextra to signify that this is an offshore tx
		std::string offshore_data = from_asset_type + "-" + to_asset_type;
    	cryptonote::add_offshore_to_tx_extra(extra, offshore_data);

        if (from_asset_type == "XHV") {
          offshore = true;
        } else if (to_asset_type == "XHV") {
          onshore = true;
        } else if ((from_asset_type == "XUSD") && (to_asset_type == "XUSD")) {
          offshore_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xUSD transfers locked to low priority");
            simple_priority = 1;
          }
        } else if ((from_asset_type != "XUSD") && (to_asset_type != "XUSD")) {
          xasset_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xAsset transfers locked to low priority");
            simple_priority = 1;
          }
        } else if (from_asset_type == "XUSD") {
          xusd_to_xasset = true;
        } else {
          xasset_to_xusd = true;
        }
	}

	if (offshore || onshore || xusd_to_xasset || xasset_to_xusd) {
      // Only permit input amounts to 4 decimal places, to avoid precision / truncation errors
      THROW_WALLET_EXCEPTION_IF(sending_amount % 100000000, error::wallet_internal_error, "Offshore/xAsset TX amounts permit at most 4 decimal places");
	}

	const uint64_t base_fee_orig = get_base_fee(fee_per_b); // in other words, fee_per_b
	uint64_t base_fee = convert_base_fee_to_source_asset_type(base_fee_orig, from_asset_type, to_asset_type, pr);
	const uint64_t fee_multiplier = get_fee_multiplier(simple_priority, default_priority(), get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn);
	//
	uint64_t attempt_at_min_fee;
	if (passedIn_attemptAt_fee == none) {
		uint64_t attempt_at_min_fee = estimate_fee(true/*use_per_byte_fee*/, true/*use_rct*/, 2/*est num inputs*/, fake_outs_count, 2, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);
		// opted to do this instead of `const uint64_t min_fee = (fee_multiplier * base_fee * estimate_tx_size(use_rct, 1, fake_outs_count, 2, extra.size(), bulletproof));`
		// TODO: estimate with 1 input or 2?
	} else {
		attempt_at_min_fee = *passedIn_attemptAt_fee;
	}

	// convert sending_amount to source asset type to use in the search for inputs from unspent outs
	uint64_t sending_amount_in_source_currency;
	if (offshore) {
		// Input amount is in XHV - no conversion needed
		sending_amount_in_source_currency = sending_amount;		
	} else if (onshore) {
		// Input amount is in XHV - convert to XUSD
		sending_amount_in_source_currency = get_xusd_amount(sending_amount, to_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(sending_amount_in_source_currency == 0, error::wallet_internal_error, "Failed to convert sending_amount back to xUSD");
	} else if (offshore_transfer) {
		// Input amount is in XUSD - no conversion needed
		sending_amount_in_source_currency = sending_amount;
	} else if (xusd_to_xasset) {
		// Input amount is in XUSD - no conversion needed
		sending_amount_in_source_currency = sending_amount;
	} else if (xasset_to_xusd) {
		// Input amount is in XUSD - convert to XASSET
		sending_amount_in_source_currency = get_xasset_amount(sending_amount, from_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(sending_amount_in_source_currency == 0, error::wallet_internal_error, "Failed to convert sending_amount to xAsset");
	} else if (xasset_transfer) {
		// Input amount is in XASSET - no conversion needed
		sending_amount_in_source_currency = sending_amount;
	} else {
		// Input amount is in XHV - no conversion needed
		sending_amount_in_source_currency = sending_amount;
	}

	// fee may get changed as follows…
	uint64_t potential_total; // aka balance_required
	if (is_sweeping) {
		potential_total = UINT64_MAX; // balance required: all
	} else {
		potential_total = sending_amount_in_source_currency + attempt_at_min_fee;
	}
	//
	// Gather outputs and amount to use for getting decoy outputs…
	uint64_t using_outs_amount = 0;
	vector<SpendableOutput>  remaining_unusedOuts = unspent_outs; // take copy so not to modify original
	// TODO: factor this out to get spendable balance for display in the MM wallet:
	while (using_outs_amount < potential_total && remaining_unusedOuts.size() > 0) {
		auto out = pop_random_value(remaining_unusedOuts);
		if (!use_rct && (out.rct != none && (*out.rct).empty() == false)) {
			// out.rct is set by the server
			continue; // skip rct outputs if not creating rct tx
		}
		if (out.amount < monero_fork_rules::dust_threshold()) { // amount is dusty..
			if (out.rct == none || (*out.rct).empty()) {
//				cout << "Found a dusty but unmixable (non-rct) output... skipping it!" << endl;
				continue;
			} else {
//				cout << "Found a dusty but mixable (rct) amount... keeping it!" << endl;
			}
		}
		using_outs_amount += out.amount;
//		cout << "Using output: " << out.amount << " - " << out.public_key << endl;
		retVals.using_outs.push_back(std::move(out));
	}
	retVals.spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
	// Note: using_outs and using_outs_amount may still get modified below (so retVals.spendable_balance gets updated)
	//
//	if (/*using_outs.size() > 1*/ && use_rct) { // FIXME? see original core js
	uint64_t needed_fee = estimate_fee(
		true/*use_per_byte_fee*/, use_rct,
		retVals.using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
		bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
	);
	// Calculate the offshore fee
	uint64_t total_for_offshore_fee = is_sweeping ? using_outs_amount : sending_amount_in_source_currency;
	uint64_t offshore_fee = (offshore) ? get_offshore_fee(total_for_offshore_fee, simple_priority)
		: (onshore) ? get_onshore_fee(total_for_offshore_fee, simple_priority)
		: (offshore_transfer) ? get_offshore_to_offshore_fee(total_for_offshore_fee, 4)
		: (xusd_to_xasset) ? get_xusd_to_xasset_fee(total_for_offshore_fee, simple_priority, use_fork_rules_fn)
		: (xasset_to_xusd) ? get_xasset_to_xusd_fee(total_for_offshore_fee, simple_priority, use_fork_rules_fn)
		: (xasset_transfer) ? get_xasset_transfer_fee(total_for_offshore_fee, simple_priority)
		: 0;
	needed_fee += offshore_fee;
	//
	// if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
	if (needed_fee < attempt_at_min_fee) {
		needed_fee = attempt_at_min_fee;
	}
	//
	// NOTE: needed_fee may get further modified below when !is_sweeping if using_outs_amount < total_incl_fees and gets finalized (for this function's scope) as using_fee
	//
	retVals.required_balance = is_sweeping ? needed_fee : potential_total; // must store for needMoreMoneyThanFound return .... NOTE: this is set to needed_fee for is_sweeping because that's literally the required balance, which an caller may want to print in case they get needMoreMoneyThanFound - note this gets updated below when !is_sweeping
	//
	uint64_t total_wo_fee = is_sweeping
		? /*now that we know outsAmount>needed_fee*/(using_outs_amount - needed_fee)
		: sending_amount_in_source_currency;
	retVals.final_total_wo_fee = total_wo_fee;
	//
	uint64_t total_incl_fees;
	if (is_sweeping) {
		if (using_outs_amount < needed_fee) { // like checking if the result of the following total_wo_fee is < 0
			retVals.errCode = needMoreMoneyThanFound; // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point
			return;
		}
		total_incl_fees = using_outs_amount;
	} else {
		total_incl_fees = sending_amount_in_source_currency + needed_fee; // because fee changed because using_outs.size() was updated
		while (using_outs_amount < total_incl_fees && remaining_unusedOuts.size() > 0) { // add outputs 1 at a time till we either have them all or can meet the fee
			{
				auto out = pop_random_value(remaining_unusedOuts);
//				cout << "Using output: " << out.amount << " - " << out.public_key << endl;
				using_outs_amount += out.amount;
				retVals.using_outs.push_back(std::move(out));
			}
			retVals.spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
			//
			// Recalculate fee, total incl fees
			needed_fee = estimate_fee(
				true/*use_per_byte_fee*/, use_rct,
				retVals.using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
				bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
			);
			needed_fee += offshore_fee;
			total_incl_fees = sending_amount_in_source_currency + needed_fee; // because fee changed
		}
		retVals.required_balance = total_incl_fees; // update required_balance b/c total_incl_fees changed
	}
	retVals.using_fee = needed_fee;
	//
//	cout << "Final attempt at fee: " << needed_fee << " for " << retVals.using_outs.size() << " inputs" << endl;
//	cout << "Balance to be used: " << total_incl_fees << endl;
	if (using_outs_amount < total_incl_fees) {
		retVals.errCode = needMoreMoneyThanFound; // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point.
		return;
	}
	//
	// Change can now be calculated
	uint64_t change_amount = 0; // to initialize
	if (using_outs_amount > total_incl_fees) {
		THROW_WALLET_EXCEPTION_IF(is_sweeping, error::wallet_internal_error, "Unexpected total_incl_fees > using_outs_amount while sweeping");
		change_amount = using_outs_amount - total_incl_fees; // change amount is in source currency type
	}
//	cout << "Calculated change amount:" << change_amount << endl;
	retVals.change_amount = change_amount;
	//
//	uint64_t tx_estimated_weight = estimate_tx_weight(true/*use_rct*/, retVals.using_outs.size(), fake_outs_count, 1+1, extra.size(), true/*bulletproof*/);
//	if (tx_estimated_weight >= TX_WEIGHT_TARGET(get_upper_transaction_weight_limit(0, use_fork_rules_fn))) {
//		// TODO?
//	}
}
void monero_transfer_utils::send_step2__try_create_transaction(
	Send_Step2_RetVals &retVals,
	//
	const string &from_address_string,
	const string &sec_viewKey_string,
	const string &sec_spendKey_string,
	const string &to_address_string,
	const string &from_asset_type,
	const string &to_asset_type,
	const optional<string>& payment_id_string,
	uint64_t final_total_wo_fee,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint32_t simple_priority,
	const vector<SpendableOutput> &using_outs,
	uint64_t fee_per_b, // per v8
	uint64_t fee_quantization_mask,
	vector<RandomAmountOutputs> &mix_outs, // cannot be const due to convenience__create_transaction's mutability requirement
	uint64_t current_height,
	offshore::pricing_record pr,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time, // or 0
	cryptonote::network_type nettype
) {
	retVals = {};
	//
	Convenience_TransactionConstruction_RetVals create_tx__retVals;
	monero_transfer_utils::convenience__create_transaction(
		create_tx__retVals,
		from_address_string,
		sec_viewKey_string, sec_spendKey_string,
		to_address_string, 
		from_asset_type, to_asset_type,
		payment_id_string,
		final_total_wo_fee, change_amount, fee_amount, simple_priority,
		using_outs, mix_outs,
		current_height, pr,
		use_fork_rules_fn,
		unlock_time,
		nettype // TODO: move to after from_address_string
	);
	if (create_tx__retVals.errCode != noError) {
		retVals.errCode = create_tx__retVals.errCode;
		return;
	}
	THROW_WALLET_EXCEPTION_IF(create_tx__retVals.signed_serialized_tx_string == boost::none, error::wallet_internal_error, "Not expecting no signed_serialized_tx_string given no error");
	//
	bool offshore = false;
	bool onshore = false;
	bool offshore_transfer = false;
	bool xasset_transfer = false;
	bool xasset_to_xusd = false;
	bool xusd_to_xasset = false;
    if (from_asset_type != "XHV" || to_asset_type != "XHV") {
        if (from_asset_type == "XHV") {
          offshore = true;
        } else if (to_asset_type == "XHV") {
          onshore = true;
        } else if ((from_asset_type == "XUSD") && (to_asset_type == "XUSD")) {
          offshore_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xUSD transfers locked to low priority");
            simple_priority = 1;
          }
        } else if ((from_asset_type != "XUSD") && (to_asset_type != "XUSD")) {
          xasset_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xAsset transfers locked to low priority");
            simple_priority = 1;
          }
        } else if (from_asset_type == "XUSD") {
          xusd_to_xasset = true;
        } else {
          xasset_to_xusd = true;
        }
	}
	uint64_t offshore_fee = (offshore) ? get_offshore_fee(final_total_wo_fee, simple_priority)
		: (onshore) ? get_onshore_fee(final_total_wo_fee, simple_priority)
		: (offshore_transfer) ? get_offshore_to_offshore_fee(final_total_wo_fee, 4)
		: (xusd_to_xasset) ? get_xusd_to_xasset_fee(final_total_wo_fee, simple_priority, use_fork_rules_fn)
		: (xasset_to_xusd) ? get_xasset_to_xusd_fee(final_total_wo_fee, simple_priority, use_fork_rules_fn)
		: (xasset_transfer) ? get_xasset_transfer_fee(final_total_wo_fee, simple_priority)
		: 0;
	//
	size_t blob_size = *create_tx__retVals.txBlob_byteLength;
	const uint64_t base_fee_orig = get_base_fee(fee_per_b); // in other words, fee_per_b
	uint64_t base_fee = convert_base_fee_to_source_asset_type(base_fee_orig, from_asset_type, to_asset_type, pr);
	uint64_t fee_actually_needed = calculate_fee(
		true/*use_per_byte_fee*/,
		*create_tx__retVals.tx, blob_size,
		base_fee,
		get_fee_multiplier(simple_priority, default_priority(), get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn),
		fee_quantization_mask
	);
	fee_actually_needed += offshore_fee;
	if (fee_actually_needed > fee_amount) {
//		cout << "Need to reconstruct tx with fee of at least " << fee_actually_needed << "." << endl;
		retVals.tx_must_be_reconstructed = true;
		retVals.fee_actually_needed = fee_actually_needed;
		return;
	}
	retVals.signed_serialized_tx_string = std::move(*(create_tx__retVals.signed_serialized_tx_string));
	retVals.tx_hash_string = std::move(*(create_tx__retVals.tx_hash_string));
	retVals.tx_key_string = std::move(*(create_tx__retVals.tx_key_string));
	retVals.tx_pub_key_string = std::move(*(create_tx__retVals.tx_pub_key_string));
}
//
//
// Underlying implementations to mimic historical JS-land create_transaction / construct_tx impls
//
void monero_transfer_utils::create_transaction(
	TransactionConstruction_RetVals &retVals,
	const account_keys& sender_account_keys, // this will reference a particular hw::device
	const uint32_t subaddr_account_idx,
	const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
	const address_parse_info &to_addr,
	const string &from_asset_type,
	const string &to_asset_type,
	uint64_t sending_amount_in_source_currency,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint64_t simple_priority,
	const vector<SpendableOutput> &outputs,
	vector<RandomAmountOutputs> &mix_outs, 
	std::vector<uint8_t> &extra,
	uint64_t current_height,
	offshore::pricing_record pr,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time, // or 0
	bool rct,
	cryptonote::network_type nettype
) {
	retVals.errCode = noError;
	//
	// TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
	//
	uint32_t fake_outputs_count = fixed_mixinsize();
	bool bulletproof = true;
	rct::RangeProofType range_proof_type = bulletproof ? rct::RangeProofPaddedBulletproof : rct::RangeProofBorromean;
	int bp_version = bulletproof ? (use_fork_rules_fn(HF_VERSION_XASSET_FULL, 0) ? 4 : (use_fork_rules_fn(HF_VERSION_CLSAG, 0) ? 3 : (use_fork_rules_fn(HF_VERSION_SMALLER_BP, -10) ? 2 : 1))) : 0;
	const rct::RCTConfig rct_config {
		range_proof_type,
		bp_version,
	};
	//
	// check both from_asset_type and to_asset_type are supported.
	if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), from_asset_type) == offshore::ASSET_TYPES.end()) {
		THROW_WALLET_EXCEPTION_IF(1, error::wallet_internal_error, "Unsupported Source Asset Type!");
	}
	if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), to_asset_type) == offshore::ASSET_TYPES.end()) {
		THROW_WALLET_EXCEPTION_IF(1, error::wallet_internal_error,  "Unsupported Dest Asset Type!");
	}
	//
	if (mix_outs.size() != outputs.size() && fake_outputs_count != 0) {
		retVals.errCode = wrongNumberOfMixOutsProvided;
		return;
	}
	for (size_t i = 0; i < mix_outs.size(); i++) {
		if (mix_outs[i].outputs.size() < fake_outputs_count) {
			retVals.errCode = notEnoughOutputsForMixing;
			return;
		}
	}
	if (!sender_account_keys.get_device().verify_keys(sender_account_keys.m_spend_secret_key, sender_account_keys.m_account_address.m_spend_public_key)
		|| !sender_account_keys.get_device().verify_keys(sender_account_keys.m_view_secret_key, sender_account_keys.m_account_address.m_view_public_key)) {
		retVals.errCode = invalidSecretKeys;
		return;
	}
	uint64_t found_money = 0;
	std::vector<tx_source_entry> sources;
	// TODO: log: "Selected transfers: " << outputs
	for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
		found_money += outputs[out_index].amount;
		if (found_money > UINT64_MAX) {
			retVals.errCode = inputAmountOverflow;
		}
		auto src = tx_source_entry{};
		src.amount = outputs[out_index].amount;
		src.asset_type = from_asset_type;
		src.rct = outputs[out_index].rct != none && (*(outputs[out_index].rct)).empty() == false;
		//
		typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
		if (mix_outs.size() != 0) {
			// Sort fake outputs by global index
			std::sort(mix_outs[out_index].outputs.begin(), mix_outs[out_index].outputs.end(), [] (
				RandomAmountOutput const& a,
				RandomAmountOutput const& b
			) {
				return a.global_index < b.global_index;
			});
			for (
				size_t j = 0;
				src.outputs.size() < fake_outputs_count && j < mix_outs[out_index].outputs.size();
				j++
			) {
				auto mix_out__output = mix_outs[out_index].outputs[j];
				if (mix_out__output.global_index == outputs[out_index].global_index) {
					LOG_PRINT_L2("got mixin the same as output, skipping");
					continue;
				}
				auto oe = tx_output_entry{};
				oe.first = mix_out__output.global_index;
				//
				crypto::public_key public_key = AUTO_VAL_INIT(public_key);
				if(!string_tools::hex_to_pod(mix_out__output.public_key, public_key)) {
					retVals.errCode = givenAnInvalidPubKey;
					return;
				}
				oe.second.dest = rct::pk2rct(public_key);
				//
				if (mix_out__output.rct != boost::none && (*(mix_out__output.rct)).empty() == false) {
					rct::key commit;
					_rct_hex_to_rct_commit(*mix_out__output.rct, commit);
					oe.second.mask = commit;
				} else {
					if (outputs[out_index].rct != boost::none && (*(outputs[out_index].rct)).empty() == false) {
						retVals.errCode = mixRCTOutsMissingCommit;
						return;
					}
					oe.second.mask = rct::zeroCommit(src.amount); //create identity-masked commitment for non-rct mix input
				}
				src.outputs.push_back(oe);
			}
		}
		auto real_oe = tx_output_entry{};
		real_oe.first = outputs[out_index].global_index;
		//
		crypto::public_key public_key = AUTO_VAL_INIT(public_key);
		if(!string_tools::validate_hex(64, outputs[out_index].public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		if (!string_tools::hex_to_pod(outputs[out_index].public_key, public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		real_oe.second.dest = rct::pk2rct(public_key);
		//
		if (outputs[out_index].rct != none
				&& outputs[out_index].rct->empty() == false
				&& *outputs[out_index].rct != "coinbase") {
			rct::key commit;
			_rct_hex_to_rct_commit(*(outputs[out_index].rct), commit);
			real_oe.second.mask = commit; //add commitment for real input
		} else {
			real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/); //create identity-masked commitment for non-rct input
		}
		//
		// Add real_oe to outputs
		uint64_t real_output_index = src.outputs.size();
		for (size_t j = 0; j < src.outputs.size(); j++) {
			if (real_oe.first < src.outputs[j].first) {
				real_output_index = j;
				break;
			}
		}
		src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
		//
		crypto::public_key tx_pub_key = AUTO_VAL_INIT(tx_pub_key);
		if(!string_tools::validate_hex(64, outputs[out_index].tx_pub_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		string_tools::hex_to_pod(outputs[out_index].tx_pub_key, tx_pub_key);
		src.real_out_tx_key = tx_pub_key;
		//
		src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(extra);
		//
		src.real_output = real_output_index;
		uint64_t internal_output_index = outputs[out_index].index;
		src.real_output_in_tx_index = internal_output_index;
		//
		src.rct = outputs[out_index].rct != boost::none && (*(outputs[out_index].rct)).empty() == false;
		if (src.rct) {
			rct::key decrypted_mask;
			bool r = _rct_hex_to_decrypted_mask(
				*(outputs[out_index].rct),
				sender_account_keys.m_view_secret_key,
				tx_pub_key,
				internal_output_index,
				decrypted_mask
			);
			if (!r) {
				retVals.errCode = cantGetDecryptedMaskFromRCTHex;
				return;
			}
			src.mask = decrypted_mask;
//			rct::key calculated_commit = rct::commit(outputs[out_index].amount, decrypted_mask);
//			rct::key parsed_commit;
//			_rct_hex_to_rct_commit(*(outputs[out_index].rct), parsed_commit);
//			if (!(real_oe.second.mask == calculated_commit)) { // real_oe.second.mask==parsed_commit(outputs[out_index].rct)
//				retVals.errCode = invalidCommitOrMaskOnOutputRCT;
//				return;
//			}
		} else {
			rct::identity(src.mask); // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
		}
		// not doing multisig here yet
		src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
		sources.push_back(src);
	}
	//
	// determine if transaction is offshore and if so what type
	bool offshore = false;
	bool onshore = false;
	bool offshore_transfer = false;
	bool xasset_transfer = false;
	bool xasset_to_xusd = false;
	bool xusd_to_xasset = false;
    if (from_asset_type != "XHV" || to_asset_type != "XHV") {
		// Populate the txextra to signify that this is an offshore tx
		std::string offshore_data = from_asset_type + "-" + to_asset_type;
    	cryptonote::add_offshore_to_tx_extra(extra, offshore_data);

        if (from_asset_type == "XHV") {
          offshore = true;
        } else if (to_asset_type == "XHV") {
          onshore = true;
        } else if ((from_asset_type == "XUSD") && (to_asset_type == "XUSD")) {
          offshore_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xUSD transfers locked to low priority");
            simple_priority = 1;
          }
        } else if ((from_asset_type != "XUSD") && (to_asset_type != "XUSD")) {
          xasset_transfer = true;
          if (simple_priority > 1) {
            // NEAC: force priority of transfers to be low to mitigate the problem from being unable to convert
            LOG_PRINT_L1("transfer: forcing priority from " << simple_priority << " to LOW - xAsset transfers locked to low priority");
            simple_priority = 1;
          }
        } else if (from_asset_type == "XUSD") {
          xusd_to_xasset = true;
        } else {
          xasset_to_xusd = true;
        }
	}
	//
    // adjust unlock time for offshore/onshore tx
    if (offshore ||	onshore) {
		unlock_time = ((simple_priority == 4) ? 180 : (simple_priority == 3) ? 720 : (simple_priority == 2) ? 1440 : 5040) + current_height;
    }
	//
	// TODO: if this is a multisig wallet, create a list of multisig signers we can use
	std::vector<cryptonote::tx_destination_entry> splitted_dsts;
	cryptonote::tx_destination_entry to_dst = AUTO_VAL_INIT(to_dst);
	cryptonote::tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);

	to_dst.addr = to_addr.address;
	to_dst.asset_type = to_asset_type;
	change_dst.asset_type = from_asset_type;

	// set correct amounts on destination and change outputs
	if (offshore) {
		to_dst.amount_usd = get_xusd_amount(sending_amount_in_source_currency, from_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(to_dst.amount_usd == 0, error::wallet_internal_error, "Failed to convert sending_amount_in_source_currency to xUSD");
		to_dst.amount = sending_amount_in_source_currency;
		change_dst.amount = change_amount;
	} else if (onshore) {
		to_dst.amount = get_xusd_amount(sending_amount_in_source_currency, from_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(to_dst.amount == 0, error::wallet_internal_error, "Failed to convert sending_amount back to xUSD");
		to_dst.amount_usd = sending_amount_in_source_currency;
		change_dst.amount_usd = change_amount;
	} else if (offshore_transfer) {
		to_dst.amount_usd = sending_amount_in_source_currency;
		change_dst.amount_usd = change_amount;
	} else if (xusd_to_xasset) {
		to_dst.amount_xasset = get_xasset_amount(sending_amount_in_source_currency, to_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(to_dst.amount_xasset == 0, error::wallet_internal_error, "Failed to convert sending_amount to xAsset");
		to_dst.amount_usd = sending_amount_in_source_currency;
		change_dst.amount_usd = change_amount;
	} else if (xasset_to_xusd) {
		to_dst.amount_usd = get_xusd_amount(sending_amount_in_source_currency, from_asset_type, pr);
		THROW_WALLET_EXCEPTION_IF(to_dst.amount_usd == 0, error::wallet_internal_error, "Failed to convert sending_amount to xAsset");
		to_dst.amount_xasset = sending_amount_in_source_currency;
		change_dst.amount_xasset = change_amount;
	} else if (xasset_transfer) {
		to_dst.amount_xasset = sending_amount_in_source_currency;
		change_dst.amount_xasset = change_amount;
	} else {
		to_dst.amount = sending_amount_in_source_currency;
		change_dst.amount = change_amount;
	}

	if (sending_amount_in_source_currency > std::numeric_limits<uint64_t>::max() - change_amount
		|| sending_amount_in_source_currency + change_amount > std::numeric_limits<uint64_t>::max() - fee_amount) {
		retVals.errCode = outputAmountOverflow;
		return;
	}
	uint64_t needed_money = sending_amount_in_source_currency + change_amount + fee_amount;

	to_dst.is_subaddress = to_addr.is_subaddress;
	splitted_dsts.push_back(to_dst);
	//
	if (change_amount == 0) {
		if (splitted_dsts.size() == 1) {
			// If the change is 0, send it to a random address, to avoid confusing
			// the sender with a 0 amount output. We send a 0 amount in order to avoid
			// letting the destination be able to work out which of the inputs is the
			// real one in our rings
			LOG_PRINT_L2("generating dummy address for 0 change");
			cryptonote::account_base dummy;
			dummy.generate();
			change_dst.addr = dummy.get_keys().m_account_address;
			LOG_PRINT_L2("generated dummy address for 0 change");
			splitted_dsts.push_back(change_dst);
		}
	} else {
		change_dst.addr = sender_account_keys.m_account_address;
		splitted_dsts.push_back(change_dst);
	}
	//
	// TODO: log: "sources: " << sources
	if (found_money > needed_money) {
		if (found_money - sending_amount_in_source_currency - change_amount != fee_amount) {
			retVals.errCode = resultFeeNotEqualToGiven; // aka "early fee calculation != later"
			return; // early
		}
	} else if (found_money < needed_money) {
		retVals.errCode = needMoreMoneyThanFound; // TODO: return actual found_money and needed_money in generalized err params in return val
		return;
	}
	//
	cryptonote::transaction tx;
	crypto::secret_key tx_key;
	std::vector<crypto::secret_key> additional_tx_keys;
	transaction_type tx_type;
	if (!get_tx_type(to_asset_type, from_asset_type, tx_type)) 
	{
		retVals.errCode = invalidAssetTypes;
		return;
	}
	uint32_t fees_version = use_fork_rules_fn(HF_PER_OUTPUT_UNLOCK_VERSION, 0) ? 4 : use_fork_rules_fn(HF_VERSION_XASSET_FEES_V2, 0) ? 3 : use_fork_rules_fn(HF_VERSION_OFFSHORE_FEES_V2, 0) ? 2 : 1;
	bool use_offshore_tx_version = use_fork_rules_fn(HF_VERSION_OFFSHORE_FULL, 0);
	//TODO check posibility to fetch hf version dynamically
	uint32_t hf_version = HF_PER_OUTPUT_UNLOCK_VERSION;
	bool r = cryptonote::construct_tx_and_get_tx_key(
		sender_account_keys, subaddresses,
		sources, splitted_dsts, change_dst.addr, extra,
		tx, tx_type, to_asset_type, from_asset_type, unlock_time, tx_key, additional_tx_keys,
		current_height - 1, pr, fees_version, hf_version, 
		true, rct_config,
		/*m_multisig ? &msout : */NULL
	);
	LOG_PRINT_L2("constructed tx, r="<<r);
	if (!r) {
		// TODO: return error::tx_not_constructed, sources, dsts, unlock_time, nettype
		retVals.errCode = transactionNotConstructed;
		return;
	}
	if (get_upper_transaction_weight_limit(0, use_fork_rules_fn) <= get_transaction_weight(tx)) {
		// TODO: return error::tx_too_big, tx, upper_transaction_weight_limit
		retVals.errCode = transactionTooBig;
		return;
	}
	bool use_bulletproofs = !tx.rct_signatures.p.bulletproofs.empty();
	THROW_WALLET_EXCEPTION_IF(use_bulletproofs != bulletproof, error::wallet_internal_error, "Expected tx use_bulletproofs to equal bulletproof flag");
	//
	retVals.tx = tx;
	retVals.tx_key = tx_key;
	retVals.additional_tx_keys = additional_tx_keys;
}
//
void monero_transfer_utils::convenience__create_transaction(
	Convenience_TransactionConstruction_RetVals &retVals,
	const string &from_address_string,
	const string &sec_viewKey_string,
	const string &sec_spendKey_string,
	const string &to_address_string,
	const string &from_asset_type,
	const string &to_asset_type,
	const optional<string>& payment_id_string,
	uint64_t sending_amount_in_source_currency,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint64_t simple_priority,
	const vector<SpendableOutput> &outputs,
	vector<RandomAmountOutputs> &mix_outs,
	uint64_t current_height,
	offshore::pricing_record pr,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time,
	network_type nettype
) {
	retVals.errCode = noError;
	//
	cryptonote::address_parse_info from_addr_info;
	THROW_WALLET_EXCEPTION_IF(!cryptonote::get_account_address_from_str(from_addr_info, nettype, from_address_string), error::wallet_internal_error, "Couldn't parse from-address");
	cryptonote::account_keys account_keys;
	{
		account_keys.m_account_address = from_addr_info.address;
		//
		crypto::secret_key sec_viewKey;
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(sec_viewKey_string, sec_viewKey), error::wallet_internal_error, "Couldn't parse view key");
		account_keys.m_view_secret_key = sec_viewKey;
		//
		crypto::secret_key sec_spendKey;
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(sec_spendKey_string, sec_spendKey), error::wallet_internal_error, "Couldn't parse spend key");
		account_keys.m_spend_secret_key = sec_spendKey;
	}
	THROW_WALLET_EXCEPTION_IF(
		to_address_string.find(".") != std::string::npos, // assumed to be an OA address asXMR addresses do not have periods and OA addrs must
		error::wallet_internal_error,
		"Integrators must resolve OA addresses before calling Send"
	); // This would be an app code fault
	cryptonote::address_parse_info to_addr_info; // just in case…
	if (!cryptonote::get_account_address_from_str(to_addr_info, nettype, to_address_string)) {
		retVals.errCode = couldntDecodeToAddress;
		return;
	}
	//
	std::vector<uint8_t> extra;
	CreateTransactionErrorCode tx_extra__code = _add_pid_to_tx_extra(payment_id_string, extra);
	if (tx_extra__code != noError) {
		retVals.errCode = tx_extra__code;
		return;
	}
	bool payment_id_seen = payment_id_string != none; // logically this is true since payment_id_string has passed validation (or we'd have errored)
	if (to_addr_info.is_subaddress && payment_id_seen) {
		retVals.errCode = cantUsePIDWithSubAddress; // Never use a subaddress with a payment ID
		return;
	}
	if (to_addr_info.has_payment_id) {
		if (payment_id_seen) {
			retVals.errCode = nonZeroPIDWithIntAddress; // can't use int addr at same time as supplying manual pid
			return;
		}
		if (to_addr_info.is_subaddress) {
			THROW_WALLET_EXCEPTION_IF(false, error::wallet_internal_error, "Unexpected is_subaddress && has_payment_id"); // should never happen
			return;
		}
		std::string extra_nonce;
		cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, to_addr_info.payment_id);
		bool r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
		if (!r) {
			retVals.errCode = couldntAddPIDNonceToTXExtra;
			return;
		}
		payment_id_seen = true;
	}
	//
	uint32_t subaddr_account_idx = 0;
	std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
	subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
	//
	TransactionConstruction_RetVals actualCall_retVals;
	create_transaction(
		actualCall_retVals,
		account_keys, subaddr_account_idx, subaddresses,
		to_addr_info,
		from_asset_type, to_asset_type,
		sending_amount_in_source_currency, change_amount, fee_amount, simple_priority,
		outputs, mix_outs,
		extra, // TODO: move to after address
		current_height, pr,
		use_fork_rules_fn,
		unlock_time, true/*rct*/, nettype
	);
	if (actualCall_retVals.errCode != noError) {
		retVals.errCode = actualCall_retVals.errCode; // pass-through
		return; // already set the error
	}
	auto txBlob = t_serializable_object_to_blob(*actualCall_retVals.tx);
	size_t txBlob_byteLength = txBlob.size();
	//	cout << "txBlob: " << txBlob << endl;
//	cout << "txBlob_byteLength: " << txBlob_byteLength << endl;
	THROW_WALLET_EXCEPTION_IF(txBlob_byteLength <= 0, error::wallet_internal_error, "Expected tx blob byte length > 0");
	//
	// tx hash
	retVals.tx_hash_string = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(*actualCall_retVals.tx));
	// signed serialized tx
	retVals.signed_serialized_tx_string = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(*actualCall_retVals.tx));
	// (concatenated) tx key
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(*actualCall_retVals.tx_key);
		for (size_t i = 0; i < (*actualCall_retVals.additional_tx_keys).size(); ++i) {
			oss << epee::string_tools::pod_to_hex((*actualCall_retVals.additional_tx_keys)[i]);
		}
		retVals.tx_key_string = oss.str();
	}
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(get_tx_pub_key_from_extra(*actualCall_retVals.tx));
		retVals.tx_pub_key_string = oss.str();
	}
	retVals.tx = *actualCall_retVals.tx; // for calculating block weight; FIXME: std::move?
	//
//	cout << "out 0: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[0].target).key) << endl;
//	cout << "out 1: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[1].target).key) << endl;
	//	
	retVals.txBlob_byteLength = txBlob_byteLength;
}
