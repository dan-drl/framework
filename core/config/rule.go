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

package config

// Rule is container of rules
type Rule struct {
	Contain []string `config:"contain"`
	Prefix  []string `config:"prefix"`
	Suffix  []string `config:"suffix"`
	Regex   []string `config:"regex"`
}

// Rules defines two fields,
// Should means any of the rules matched will be work
// Must means some rule must match
// MustNot means some rule must not match
type Rules struct {
	Should  *Rule `config:"should"`
	Must    *Rule `config:"must"`
	MustNot *Rule `config:"must_not"`
}
