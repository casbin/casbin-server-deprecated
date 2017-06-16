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

func TestModel(t *testing.T) {
	testEnforce(t, "tenant1", "alice", "data1", "read", "nova", true)
}
