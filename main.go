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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/gin-gonic/gin"
)

type SecurityContext struct {
	Tenant string
	Sub string
	Obj string
	Act string
}



func handleRequest(c *gin.Context) {
	r := c.Request

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var sc SecurityContext
	err = json.Unmarshal(body, &sc)
	if err != nil {
		panic(err)
	}

	res := enforce(sc.Tenant, sc.Sub, sc.Obj, sc.Act)
	fmt.Println("Request: ", sc, " ---> ", res)

	res_str := strconv.FormatBool(res)
	c.JSON(200, gin.H{
		"decision": res_str,
	})
}

func main() {
	r := gin.Default()
	r.POST("/decision", handleRequest)
	r.Run() // listen and serve on 0.0.0.0:8080
}
