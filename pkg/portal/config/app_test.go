package config

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAppConfigGetLatestAppHost(t *testing.T) {
	Convey("AppConfig#GetLatestAppHost", t, func() {
		test := func(suffix string, appID string, expected string) {
			appConfig := &AppConfig{}
			appConfig.HostSuffix = suffix
			if expected == "" {
				So(func() {
					_ = appConfig.GetLatestAppHost(appID)
				}, ShouldPanicWith, fmt.Errorf("APP_HOST_SUFFIX is not configured"))
			} else {
				actual := appConfig.GetLatestAppHost(appID)
				So(actual, ShouldEqual, expected)
			}
		}

		test("", "myapp", "")
		test(".localhost", "myapp", "myapp.localhost")
		test(".localhost:3100", "myapp", "myapp.localhost:3100")

	})
}
