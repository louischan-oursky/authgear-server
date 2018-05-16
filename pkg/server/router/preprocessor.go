// Copyright 2015-present Oursky Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package router

import (
	"fmt"
)

//
// PreprocessorRegistry is holding all preprocessors and their mapping with
// a string name.
type PreprocessorRegistry map[string]Processor

// GetByNames returns a list of registered preprocessors by preprocessor names.
func (r PreprocessorRegistry) GetByNames(names ...string) []Processor {
	preprocessors := make([]Processor, len(names))
	for i, name := range names {
		pp, ok := r[name]
		if !ok {
			panic(fmt.Sprintf("preprocessor %s is not defined", name))
		}
		preprocessors[i] = pp
	}
	return preprocessors
}
