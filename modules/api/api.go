/*
Copyright 2016 Medcl (m AT medcl.net)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"github.com/dan-drl/framework/core/api"
	"github.com/dan-drl/framework/core/config"
)

// Name return API
func (module APIModule) Name() string {
	return "API"
}

// Start api server
func (module APIModule) Setup(cfg *config.Config) {
	//API server
	api.StartAPI(cfg)
}
func (module APIModule) Start() error {

	return nil
}

// Stop api server
func (module APIModule) Stop() error {
	return nil
}

// APIModule is used to start API server
type APIModule struct {
}
