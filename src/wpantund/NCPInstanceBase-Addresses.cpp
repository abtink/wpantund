/*
 *
 * Copyright (c) 2016 Nest Labs, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include "NCPInstanceBase.h"
#include "tunnel.h"
#include <syslog.h>
#include <errno.h>
#include "nlpt.h"
#include <algorithm>
#include "socket-utils.h"
#include "SuperSocket.h"

using namespace nl;
using namespace wpantund;

NCPInstanceBase::UnicastAddressEntry::UnicastAddressEntry(
    Origin origin,
    uint32_t valid_lifetime,
    uint32_t preferred_lifetime
) :	EntryBase(origin)
{
	set_valid_lifetime(valid_lifetime);
	set_preferred_lifetime(preferred_lifetime);
}

void
NCPInstanceBase::UnicastAddressEntry::set_valid_lifetime(uint32_t valid_lifetime)
{
	mValidLifetime = valid_lifetime;

	mValidLifetimeExpiration = (valid_lifetime == UINT32_MAX)
		? TIME_DISTANT_FUTURE
		: time_get_monotonic() + valid_lifetime;
}

void
NCPInstanceBase::UnicastAddressEntry::set_preferred_lifetime(uint32_t preferred_lifetime)
{
	mPreferredLifetime = preferred_lifetime;

	mPreferredLifetimeExpiration = ((mPreferredLifetime == UINT32_MAX)
		? TIME_DISTANT_FUTURE
		: time_get_monotonic() + preferred_lifetime
	);
}

std::string
NCPInstanceBase::UnicastAddressEntry::get_description(void) const
{
	char c_string[200];

	snprintf(c_string, sizeof(c_string), "valid:%u  preferred:%u origin:%s", mValidLifetime, mPreferredLifetime,
				get_origin() == kOriginThreadNCP ? "ncp" : "user");

	return std::string(c_string);
}

void
NCPInstanceBase::refresh_global_addresses(void)
{
	// Here is where we would do any periodic global address bookkeeping,
	// which doesn't appear to be necessary yet but may become necessary
	// in the future.
}

void
NCPInstanceBase::clear_all_global_entries(void)
{
	mUnicastAddresses.clear();
	mMulticastAddresses.clear();
	mOnMeshPrefixes.clear();
}

void
NCPInstanceBase::clear_ncp_originated_entries(void)
{
	bool did_remove = false;

	std::map<struct in6_addr, UnicastAddressEntry>::iterator iter;

	// We want to remove all of the addresses/prefixes that
	// did not originate from interface (i.e. not user added).

	do {
		did_remove = false;

		for (
			std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
			iter != mUnicastAddresses.end();
			++iter
		) {
			// Skip the removal of addresses from interface
			if (iter->second.is_from_interface()) {
				continue;
			}

			mPrimaryInterface->remove_address(&iter->first);
			mUnicastAddresses.erase(iter);
			did_remove = true;

			// Break out of the inner loop so that we start over.
			break;
		}
	} while (did_remove);
}

void
NCPInstanceBase::restore_global_addresses(void)
{
	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
	std::map<struct in6_addr, UnicastAddressEntry> global_addresses(mUnicastAddresses);

	mUnicastAddresses.clear();

	for (iter = global_addresses.begin(); iter!= global_addresses.end(); ++iter) {
		if (iter->second.is_from_interface()) {
			address_was_added(iter->first, 64);
		}
		mUnicastAddresses.insert(*iter);

		mPrimaryInterface->add_address(&iter->first);
	}
}

void
NCPInstanceBase::add_unicast_address(const struct in6_addr &address, uint8_t prefix, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	UnicastAddressEntry entry = UnicastAddressEntry(kOriginThreadNCP, valid_lifetime, preferred_lifetime);

	if (mUnicastAddresses.count(address)) {
		syslog(LOG_INFO, "Updating IPv6 Address...");
	} else {
		syslog(LOG_INFO, "Adding IPv6 Address...");
		mPrimaryInterface->add_address(&address);
	}

	mUnicastAddresses[address] = entry;
}

void
NCPInstanceBase::remove_unicast_address(const struct in6_addr &address)
{
	mUnicastAddresses.erase(address);
	mPrimaryInterface->remove_address(&address);
}

bool
NCPInstanceBase::is_address_known(const struct in6_addr &address)
{
	bool ret(mUnicastAddresses.count(address) != 0);

	return ret;
}

bool
NCPInstanceBase::lookup_address_for_prefix(struct in6_addr *address, const struct in6_addr &prefix, int prefix_len_in_bits)
{
	struct in6_addr masked_prefix(prefix);

	in6_addr_apply_mask(masked_prefix, prefix_len_in_bits);

	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
	for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
		struct in6_addr iter_prefix(iter->first);
		in6_addr_apply_mask(iter_prefix, prefix_len_in_bits);

		if (iter_prefix == masked_prefix) {
			if (address != NULL) {
				*address = iter->first;
			}
			return true;
		}
	}
	return false;
}

void
NCPInstanceBase::address_was_added(const struct in6_addr& addr, int prefix_len)
{
	char addr_cstr[INET6_ADDRSTRLEN] = "::";
	inet_ntop(
		AF_INET6,
		&addr,
		addr_cstr,
		sizeof(addr_cstr)
	);

	syslog(LOG_NOTICE, "\"%s\" was added to \"%s\"", addr_cstr, mPrimaryInterface->get_interface_name().c_str());

	if (mUnicastAddresses.count(addr) == 0) {
		mUnicastAddresses[addr] = UnicastAddressEntry(kOriginPrimaryInterface);;
	}
}

void
NCPInstanceBase::address_was_removed(const struct in6_addr& addr, int prefix_len)
{
	char addr_cstr[INET6_ADDRSTRLEN] = "::";
	inet_ntop(
		AF_INET6,
		&addr,
		addr_cstr,
		sizeof(addr_cstr)
	);

	if ((mUnicastAddresses.count(addr) != 0)
	 && (mPrimaryInterface->is_online() || !mUnicastAddresses[addr].is_from_interface())
	) {
		mUnicastAddresses.erase(addr);
	}

	syslog(LOG_NOTICE, "\"%s\" was removed from \"%s\"", addr_cstr, mPrimaryInterface->get_interface_name().c_str());
}

void
NCPInstanceBase::join_multicast_address(const struct in6_addr &address)
{
	if (!mMulticastAddresses.count(address)) {
		mMulticastAddresses[address] = MulticastAddressEntry(kOriginThreadNCP);
		mPrimaryInterface->join_multicast_address(&address);
	}
}

void
NCPInstanceBase::leave_multicast_address(const struct in6_addr &address)
{
	if (mMulticastAddresses.count(address)) {
		mMulticastAddresses.erase(address);
		mPrimaryInterface->leave_multicast_address(&address);
	}
}
