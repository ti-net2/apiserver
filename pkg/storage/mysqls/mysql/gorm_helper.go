/*

Copyright 2018 This Project Authors.

Author:  seanchann <seanchann@foxmail.com>

See docs/ for more information about the  project.

*/

package mysql

import (
	"fmt"

	"strings"

	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apiserver/pkg/storage"

	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
)

//appendQuoteToField append quote into filed for every member。
// eg 'spec.test.name' ====> '"spec"."test"."name"'
func appendQuoteToField(input string) (field string) {
	members := strings.Split(input, ".")
	if len(members) > 0 {
		var quoteMember []string
		for _, v := range members {
			m := fmt.Sprintf("\"%s\"", v)
			quoteMember = append(quoteMember, m)
		}
		field = strings.Join(quoteMember, ".")
	}

	return
}

//Fields build gorm select condition by storage.SelectionPredicate
//selectionFeild contains what field will be select for query
func selectionWithFields(dbHandle *gorm.DB, p storage.SelectionPredicate, isCount bool) *gorm.DB {
	if p.Field == nil || (p.Field != nil && p.Field.Empty()) {
		return dbHandle
	}

	fieldsCondition := p.Field.Requirements()
	for _, v := range fieldsCondition {
		switch v.Operator {
		case selection.Equals:
			fallthrough
		case selection.DoubleEquals:
			query := fmt.Sprintf("JSON_CONTAINS(%s, '%s', '$.%s') = ?",
				"obj", v.Value, appendQuoteToField(v.Field))
			queryArgs := "1"

			dbHandle = dbHandle.Where(query, queryArgs)
		case selection.NotEquals:
			query := fmt.Sprintf("JSON_CONTAINS(%s, '%s', '$.%s') = ?",
				"obj", v.Value, appendQuoteToField(v.Field))
			queryArgs := "0"

			dbHandle = dbHandle.Where(query, queryArgs)
		//TODO: this can't be support if have specific Requirements
		case selection.In:
			fallthrough
		case selection.NotIn:
			glog.Warningf("not support in and not in")
		case selection.DoesNotExist:
			fallthrough
		case selection.Exists:
			//only search obj filed for this operator,ignore count
			if isCount {
				continue
			}
			query := fmt.Sprintf("JSON_CONTAINS_PATH(%s, 'one', '$.%s') = ?",
				"obj", appendQuoteToField(v.Field))
			queryArgs := "1"
			if selection.DoesNotExist == v.Operator {
				queryArgs = "0"
			}
			dbHandle = dbHandle.Where(query, queryArgs)
		}
	}

	return dbHandle
}

func extractKey(key string) (kind, resource string) {
	keySlice := strings.Split(key, "/")
	if len(keySlice) == 3 {
		resource = keySlice[2]
		kind = keySlice[1]
	} else if len(keySlice) == 2 {
		kind = keySlice[1]
	}

	glog.Infof("extract key %v slice %v:[%v]", key, len(keySlice), keySlice)

	return
}
