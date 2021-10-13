package stdattrs

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestT(t *testing.T) {
	Convey("T", t, func() {
		Convey("NonIdentityAware", func() {
			So(T{
				"a":     "b",
				"name":  "John Doe",
				"email": "louischan@oursky.com",
			}.NonIdentityAware(), ShouldResemble, T{
				"name": "John Doe",
			})
		})

		Convey("MergedWith", func() {
			So(T{
				"a":    "b",
				"keep": "this",
			}.MergedWith(T{
				"a":   "c",
				"new": "key",
			}), ShouldResemble, T{
				"keep": "this",
				"new":  "key",
				"a":    "c",
			})
		})

		Convey("FormattedName", func() {
			So(T{
				"name": "John Doe",
			}.FormattedName(), ShouldEqual, "John Doe")
			So(T{
				"given_name":  "John",
				"family_name": "Doe",
			}.FormattedName(), ShouldEqual, "John Doe")
			So(T{
				"given_name":  "John",
				"middle_name": "William",
				"family_name": "Doe",
			}.FormattedName(), ShouldEqual, "John William Doe")
			So(T{
				"given_name":  "John",
				"family_name": "Doe",
				"nickname":    "Johnny",
			}.FormattedName(), ShouldEqual, "John Doe (Johnny)")
		})

		Convey("EndUserAccountID", func() {
			So(T{}.EndUserAccountID(), ShouldEqual, "")
			So(T{
				"email": "user@example.com",
			}.EndUserAccountID(), ShouldEqual, "user@example.com")
			So(T{
				"preferred_username": "user",
			}.EndUserAccountID(), ShouldEqual, "user")
			So(T{
				"phone_number": "+85298765432",
			}.EndUserAccountID(), ShouldEqual, "+85298765432")
			So(T{
				"preferred_username": "user",
				"phone_number":       "+85298765432",
			}.EndUserAccountID(), ShouldEqual, "user")
			So(T{
				"email":              "user@example.com",
				"preferred_username": "user",
				"phone_number":       "+85298765432",
			}.EndUserAccountID(), ShouldEqual, "user@example.com")
		})
	})
}
