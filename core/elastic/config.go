/*
Copyright Medcl (m AT medcl.net)

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

package elastic

import (
	"fmt"
	log "github.com/cihub/seelog"

)

var apis = map[string]API{}
var cfgs = map[string]ElasticsearchConfig{}

func RegisterInstance(elastic string, cfg ElasticsearchConfig, handler API) {
	if apis == nil {
		apis = map[string]API{}
	}
	if cfgs == nil {
		cfgs = map[string]ElasticsearchConfig{}
	}
	apis[elastic] = handler
	cfgs[elastic] = cfg
}

// ElasticsearchConfig contains common settings for elasticsearch
type ElasticsearchConfig struct {
	ID           string `json:"id,omitempty" index:"id"`
	Name         string `json:"name,omitempty" config:"name"`
	Enabled      bool   `json:"enabled,omitempty" config:"enabled"`
	HttpProxy    string `config:"http_proxy"`
	Endpoint     string `config:"endpoint"`
	TemplateName string `config:"template_name"`
	IndexPrefix  string `config:"index_prefix"`
	IndexSuffix  string `config:"index_suffix"`
	Engine       *struct {
		EngineID  string `json:"engineId,omitempty" config:"engine_id"`
		AccountID string `json:"accountId,omitempty" config:"account_id"`
	} `json:"engine,omitempty" config:"engine"`
	BasicAuth    *struct {
		Username string `config:"username"`
		Password string `config:"password"`
	} `config:"basic_auth"`
}


func (c* ElasticsearchConfig) Check()  {
	
	// Fail fast if key things are missing
	if c.IndexPrefix == "" {
		panic("index_prefix missing")
	}
	if c.Engine == nil {
		log.Warn("engine section missing from elastic search config.")
	} else {
		if c.Engine.EngineID == "" {
			panic("engine.engine_id missing from elastic search config.")
		}
		if c.Engine.AccountID == "" {
			panic("engine.account_id missing from elastic search config.")
		}
	}
}

func GetConfig(k string) ElasticsearchConfig {
	v, ok := cfgs[k]
	if !ok {
		panic(fmt.Sprintf("elasticsearch config %v was not found", k))
	}
	return v
}

func GetClient(k string) API {
	v, ok := apis[k]
	if !ok {
		panic(fmt.Sprintf("elasticsearch client %v was not found", k))
	}
	return v
}
