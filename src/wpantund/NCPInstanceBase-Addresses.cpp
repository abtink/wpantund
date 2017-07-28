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
#include "IPv6Helpers.h"

using namespace nl;
using namespace wpantund;

NCPInstanceBase::UnicastAddressEntry::UnicastAddressEntry(
    Origin origin,
    uint8_t prefix_len,
    uint32_t valid_lifetime,
    uint32_t preferred_lifetime
) :	EntryBase(origin)
{
	mPrefixLen = prefix_len;
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
	syslog(LOG_INFO, "Clearing all address/prefixes");

	mUnicastAddresses.clear();
	mMulticastAddresses.clear();
	mOnMeshPrefixes.clear();
}

void
NCPInstanceBase::clear_ncp_originated_entries(void)
{
	bool did_remove = false;

	// We remove all of the addresses/prefixes that originate
	// from the NCP.

	syslog(LOG_INFO, "Clearing NCP originated address/prefix entries");

	do {
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter;

		did_remove = false;

		for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); iter++) {
			if (!iter->second.is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "UnicastAddresses: Removing \"%s\" with origin NCP", in6_addr_to_string(iter->first).c_str());
			mUnicastAddresses.erase(iter);
			mPrimaryInterface->remove_address(&iter->first, iter->second.get_prefix_len());
			did_remove = true;
			break;
		}
	} while (did_remove);
}

void
NCPInstanceBase::restore_interface_originated_entries_on_ncp(void)
{
	syslog(LOG_INFO, "Restoring interface originated addresses/prefix entries on NCP");

	for (
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
		iter != mUnicastAddresses.end();
		++iter
	) {
		if (iter->second.is_from_interface())  {
			update_unicast_address_on_ncp(kEntryAdd, iter->first, iter->second.get_prefix_len());
		}
	}
}

// ABTIN: Do we need an equivalent part to do the same on the NCP?????

/*
	// Re-add the link local and mesh-local addresses (only if valid).
	if (IN6_IS_ADDR_LINKLOCAL(&mNCPLinkLocalAddress)) {
		add_unicast_address(mNCPLinkLocalAddress);
	}

	if (buffer_is_nonzero(mNCPMeshLocalAddress.s6_addr, sizeof(mNCPMeshLocalAddress)))	{
		add_unicast_address(mNCPMeshLocalAddress);
	}



	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
	std::map<struct in6_addr, UnicastAddressEntry> global_addresses(mUnicastAddresses);

	mUnicastAddresses.clear();

	for (iter = global_addresses.begin(); iter!= global_addresses.end(); ++iter) {
		if (iter->second.is_from_interface()) {
			unicast_address_was_added_on_interface(iter->first, 64);
		}
		mUnicastAddresses.insert(*iter);

		mPrimaryInterface->add_address(&iter->first);
	}
*/

void
NCPInstanceBase::add_unicast_address(const struct in6_addr &address, uint8_t prefix_len, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	if (mUnicastAddresses.count(address) == 0) {
		syslog(LOG_INFO, "UnicastAddresses: Adding \"%s/%d\" with origin NCP", in6_addr_to_string(address).c_str(), prefix_len);
		mUnicastAddresses[address] = UnicastAddressEntry(kOriginThreadNCP, prefix_len, valid_lifetime, preferred_lifetime);;
		mPrimaryInterface->add_address(&address, prefix_len);
	}
}

void
NCPInstanceBase::remove_unicast_address(const struct in6_addr &address)
{
	if (!mUnicastAddresses.count(address)) {
		// Do not allow NCP to remove addresses previously added by primary interface.
		if (mUnicastAddresses[address].is_from_ncp()) {
			uint8_t prefix_len = mUnicastAddresses[address].get_prefix_len();
			syslog(LOG_INFO, "UnicastAddresses: Removing \"%s/%d\" with origin NCP", in6_addr_to_string(address).c_str(), prefix_len);
			mPrimaryInterface->remove_address(&address, prefix_len);
			mUnicastAddresses.erase(address);
		}
	}
}

bool
NCPInstanceBase::lookup_address_for_prefix(struct in6_addr *address, const struct in6_addr &prefix, int prefix_len)
{
	struct in6_addr masked_prefix(prefix);

	in6_addr_apply_mask(masked_prefix, prefix_len);

	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
	for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
		struct in6_addr iter_prefix(iter->first);
		in6_addr_apply_mask(iter_prefix, prefix_len);

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
NCPInstanceBase::unicast_address_was_added_on_interface(const struct in6_addr& addr, uint8_t prefix_len)
{
	std::string addr_str = in6_addr_to_string(addr);

	syslog(LOG_NOTICE, "\"%s\" was added to \"%s\"", addr_str.c_str(), mPrimaryInterface->get_interface_name().c_str());

	if (mUnicastAddresses.count(addr) == 0) {
		syslog(LOG_INFO, "UnicastAddresses: Adding \"%s/%d\" with origin tunnel interface", in6_addr_to_string(addr).c_str(), prefix_len);
		mUnicastAddresses[addr] = UnicastAddressEntry(kOriginPrimaryInterface, prefix_len);
		update_unicast_address_on_ncp(kEntryAdd, addr, prefix_len);
	}
}

void
NCPInstanceBase::unicast_address_was_removed_on_interface(const struct in6_addr& addr, uint8_t prefix_len)
{
	std::string addr_str = in6_addr_to_string(addr);

	syslog(LOG_NOTICE, "\"%s\" was removed from \"%s\"", addr_str.c_str(), mPrimaryInterface->get_interface_name().c_str());

	if (mUnicastAddresses.count(addr) != 0) {
		if (mUnicastAddresses[addr].is_from_interface()) {
			mUnicastAddresses.erase(addr);
			syslog(LOG_INFO, "UnicastAddresses: Removing \"%s\" with origin tunnel interface", in6_addr_to_string(addr).c_str());
			update_unicast_address_on_ncp(kEntryRemove, addr, prefix_len);
		} else {
			syslog(LOG_INFO, "Keeping \"%s\" on NCP as it was originated from NCP", addr_str.c_str());
		}
	}
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

void
NCPInstanceBase::update_unicast_address_on_ncp(EntryAction action, const struct in6_addr &addr, uint8_t prefix_len)
{
	// This is intended for sub-classes to update address on NCP

	// NCPInstanceBase provides an empty implementation for plug-ins
	// that may not want to implement/support this.
}

void
NCPInstanceBase::update_multicast_address_on_ncp(EntryAction action, const struct in6_addr &addr)
{
	// This is intended for sub-classes to update multicast addresses on NCP

	// NCPInstanceBase provides an empty implementation for plug-ins
	// that may not want to implement/support this.
}

void
NCPInstanceBase::update_on_mesh_prefix_on_ncp(EntryAction action, const struct in6_addr &addr)
{
	// This is intended for sub-classes to update on-mesh prefixes on NCP

	// NCPInstanceBase provides an empty implementation for plug-ins
	// that may not want to implement/support this.
}

