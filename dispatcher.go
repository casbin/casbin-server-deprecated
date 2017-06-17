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
	"os"
	"runtime"

	"github.com/casbin/casbin"
)

var base_dir string

var model_global_enable string = "model/enable_model.conf"
var model_global_restrict string = "model/restrict_model.conf"
var model_custom string = "model/custom_model.conf"

var policy_global_enable string
var policy_global_restrict string
var policy_tenant1_custom string

func init() {
	if runtime.GOOS == "windows" {
		base_dir = "J:/github_repos/patron_rest/etc/patron/custom_policy/"
	} else {
		if os.Getenv("TRAVIS") == "true" {
			base_dir = "../patron_rest/etc/patron/custom_policy/"
		} else {
			base_dir = "/home/luoyang/patron_rest/etc/patron/custom_policy/"
		}
	}

	policy_global_enable = base_dir + "../enable.csv"
	policy_global_restrict = base_dir + "../restrict.csv"
	policy_tenant1_custom = base_dir + "tenant1/custom-policy.csv"
}

func enforceForFile(modelPath string, policyPath string, sc SecurityContext) bool {
	e := casbin.NewEnforcer(modelPath, policyPath)
	return e.Enforce(sc.Tenant, sc.Sub, sc.Obj, sc.Act, sc.Service)
}

func enforce(sc SecurityContext) bool {
	if sc.Tenant == "admin" {
		return true
	}

	if sc.Tenant == "1" || sc.Tenant == "2" || sc.Tenant == "4" || sc.Tenant == "9" {
		return true
	}

	if sc.Tenant == "rds" || sc.Tenant == "service" || sc.Tenant == "services" {
		return true
	}

	if sc.Tenant == "tenant1" {
		if !enforceForFile(model_global_restrict, policy_global_restrict, sc) {
			return false
		}

		if enforceForFile(model_global_enable, policy_global_enable, sc) {
			return true
		}

		return enforceForFile(model_custom, policy_tenant1_custom, sc)
	}

	if sc.Tenant == "tenant2" {
		if !enforceForFile(model_global_restrict, policy_global_restrict, sc) {
			return false
		}

		if enforceForFile(model_global_enable, policy_global_enable, sc) {
			return true
		}

		return true
	}

	if sc.Tenant == "tenant3" {
		return false
	}

	return false
}
