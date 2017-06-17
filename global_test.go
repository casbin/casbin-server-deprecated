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

import (
	"testing"
)

func testGlobalEnforce(t *testing.T, tenant string, sub string, obj string, act string, service string, res bool) {
	var sc SecurityContext
	sc.Tenant = tenant
	sc.Sub = sub
	sc.Obj = obj
	sc.Act = act
	sc.Service = service

	if enforce(sc) != res {
		t.Errorf("%s, %s, %s, %s, %s: %t, supposed to be %t", tenant, sub, obj, act, service, !res, res)
	}
}

func TestGlobalAdmin(t *testing.T) {
	// admin can access anything.
	testGlobalEnforce(t, "admin", "admin", "/", "GET", "nova", true)
	testGlobalEnforce(t, "admin", "admin", "/admin/servers/detail", "GET", "nova", true)
	testGlobalEnforce(t, "admin", "admin", "/admin/extensions", "GET", "nova", true)
	testGlobalEnforce(t, "admin", "admin", "/admin/os-simple-tenant-usage/ce9ff56f5af746de93ec30f387cd7fa8", "GET", "nova", true)
	testGlobalEnforce(t, "admin", "admin", "/admin/flavors/detail", "GET", "nova", true)
	testGlobalEnforce(t, "admin", "admin", "/admin/extensions", "GET", "nova", true)

	// tenant1 cannot access admin's VM.
	testGlobalEnforce(t, "tenant1", "user11", "/admin/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t, "tenant1", "user12", "/admin/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t, "tenant1", "user13", "/admin/servers/detail", "GET", "nova", false)

	// tenant2 cannot access admin's VM.
	testGlobalEnforce(t, "tenant2", "user2", "/admin/servers/detail", "GET", "nova", false)

	// tenant3 cannot access admin's VM.
	testGlobalEnforce(t, "tenant3", "user3", "/admin/servers/detail", "GET", "nova", false)
}

func TestGlobalEnable(t *testing.T) {
	// user11 is the tenant administrator.
	// user11 can access policy of his own tenant.
	testGlobalEnforce(t,"tenant1", "user11", "/tenant1/metadata", "GET", "patron", true)
	testGlobalEnforce(t, "tenant1", "user11", "/tenant1/metadata", "POST", "patron", true)
	testGlobalEnforce(t, "tenant1", "user11", "/tenant1/policy", "GET", "patron", true)
	testGlobalEnforce(t, "tenant1", "user11", "/tenant1/policy", "POST", "patron", true)

	// user12 cannot access policy of his own tenant.
	testGlobalEnforce(t,"tenant1", "user12", "/tenant1/metadata", "GET", "patron", false)
	testGlobalEnforce(t, "tenant1", "user12", "/tenant1/metadata", "POST", "patron", false)
	testGlobalEnforce(t, "tenant1", "user12", "/tenant1/policy", "GET", "patron", false)
	testGlobalEnforce(t, "tenant1", "user12", "/tenant1/policy", "POST", "patron", false)

	// tenant2 cannot access tenant1's policy.
	testGlobalEnforce(t,"tenant2", "user2", "/tenant1/metadata", "GET", "patron", false)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant1/metadata", "POST", "patron", false)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant1/policy", "GET", "patron", false)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant1/policy", "POST", "patron", false)

	// user2 is the tenant administrator.
	// user2 can access policy of his own tenant.
	testGlobalEnforce(t,"tenant2", "user2", "/tenant2/metadata", "GET", "patron", true)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant2/metadata", "POST", "patron", true)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant2/policy", "GET", "patron", true)
	testGlobalEnforce(t, "tenant2", "user2", "/tenant2/policy", "POST", "patron", true)

	// tenant3 cannot access anything.
	testGlobalEnforce(t,"tenant3", "user3", "/tenant3/metadata", "GET", "patron", false)
	testGlobalEnforce(t, "tenant3", "user3", "/tenant3/metadata", "POST", "patron", false)
	testGlobalEnforce(t, "tenant3", "user3", "/tenant3/policy", "GET", "patron", false)
	testGlobalEnforce(t, "tenant3", "user3", "/tenant3/policy", "POST", "patron", false)
}

func TestGlobalRestrict(t *testing.T) {
	// tenant2 and tenant3 cannot access tenant1's VM.
	testGlobalEnforce(t,"tenant2", "user2", "/tenant1/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t,"tenant3", "user3", "/tenant1/servers/detail", "GET", "nova", false)

	// tenant2 and tenant3 cannot access tenant1's disk.
	testGlobalEnforce(t,"tenant2", "user2", "/tenant1/volumes/detail", "GET", "cinder", false)
	testGlobalEnforce(t,"tenant3", "user3", "/tenant1/volumes/detail", "GET", "cinder", false)

	// tenant2 and tenant3 cannot access admin's VM.
	testGlobalEnforce(t, "tenant1", "user11", "/admin/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t, "tenant2", "user2", "/admin/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t, "tenant3", "user3", "/admin/servers/detail", "GET", "nova", false)
}

func TestGlobalTenant1(t *testing.T) {
	// user11 can access anything in tenant1.
	testGlobalEnforce(t,"tenant1", "user11", "/tenant1/servers/detail", "GET", "nova", true)
	testGlobalEnforce(t,"tenant1", "user11", "/v2/images", "GET", "glance", true)
	testGlobalEnforce(t,"tenant1", "user11", "/networks.json", "GET", "neutron", true)
	testGlobalEnforce(t,"tenant1", "user11", "/tenant1/volumes/detail", "GET", "cinder", true)

	// user12 can only access Nova.
	testGlobalEnforce(t,"tenant1", "user12", "/tenant1/servers/detail", "GET", "nova", true)
	testGlobalEnforce(t,"tenant1", "user12", "/v2/images", "GET", "glance", false)
	testGlobalEnforce(t,"tenant1", "user12", "/networks.json", "GET", "neutron", false)
	testGlobalEnforce(t,"tenant1", "user12", "/tenant1/volumes/detail", "GET", "cinder", false)

	// user13 can only access Glance.
	testGlobalEnforce(t,"tenant1", "user13", "/tenant1/servers/detail", "GET", "nova", false)
	testGlobalEnforce(t,"tenant1", "user13", "/v2/images", "GET", "glance", true)
	testGlobalEnforce(t,"tenant1", "user13", "/networks.json", "GET", "neutron", false)
	testGlobalEnforce(t,"tenant1", "user13", "/tenant1/volumes/detail", "GET", "cinder", false)
}
