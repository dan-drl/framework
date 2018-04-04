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

package util

import (
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/cihub/seelog"
)

// Post http post with a list of values
func Post(url string, values url.Values) []byte {
	r, err := http.PostForm(url, values)
	if err != nil {
		log.Error("post:", err)
		return nil
	}
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("post:", err)
		return nil
	}
	return b
}
