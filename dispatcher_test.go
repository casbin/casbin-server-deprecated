// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "testing"

func testEnforce(t *testing.T, tenant string, sub string, obj string, act string, service string, res bool) {
	var sc SecurityContext
	sc.Tenant = tenant
	sc.Sub = sub
	sc.Obj = obj
	sc.Act = act

	if enforce(sc) != res {
		t.Errorf("%s, %s, %s, %s, %s: %t, supposed to be %t", tenant, sub, obj, act, service, !res, res)
	}
}

func TestAdmin(t *testing.T) {
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/", "GET", "nova", true)
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", true)
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/ce9ff56f5af746de93ec30f387cd7fa8/extensions", "GET", "nova", true)
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/ce9ff56f5af746de93ec30f387cd7fa8/os-simple-tenant-usage/ce9ff56f5af746de93ec30f387cd7fa8", "GET", "nova", true)
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/ce9ff56f5af746de93ec30f387cd7fa8/flavors/detail", "GET", "nova", true)
	testEnforce(t, "ce9ff56f5af746de93ec30f387cd7fa8", "admin", "/ce9ff56f5af746de93ec30f387cd7fa8/extensions", "GET", "nova", true)

	testEnforce(t, "tenant1", "user1", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant1", "user2", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant1", "user3", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)

	testEnforce(t, "tenant2", "user1", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant2", "user2", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant2", "user3", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)

	testEnforce(t, "tenant3", "user1", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant3", "user2", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
	testEnforce(t, "tenant3", "user3", "/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail", "GET", "nova", false)
}
