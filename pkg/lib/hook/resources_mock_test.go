// Code generated by MockGen. DO NOT EDIT.
// Source: resources.go

// Package hook is a generated GoMock package.
package hook

import (
	reflect "reflect"

	resource "github.com/authgear/authgear-server/pkg/util/resource"
	gomock "github.com/golang/mock/gomock"
)

// MockResourceManager is a mock of ResourceManager interface.
type MockResourceManager struct {
	ctrl     *gomock.Controller
	recorder *MockResourceManagerMockRecorder
}

// MockResourceManagerMockRecorder is the mock recorder for MockResourceManager.
type MockResourceManagerMockRecorder struct {
	mock *MockResourceManager
}

// NewMockResourceManager creates a new mock instance.
func NewMockResourceManager(ctrl *gomock.Controller) *MockResourceManager {
	mock := &MockResourceManager{ctrl: ctrl}
	mock.recorder = &MockResourceManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResourceManager) EXPECT() *MockResourceManagerMockRecorder {
	return m.recorder
}

// Read mocks base method.
func (m *MockResourceManager) Read(desc resource.Descriptor, view resource.View) (interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", desc, view)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read.
func (mr *MockResourceManagerMockRecorder) Read(desc, view interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockResourceManager)(nil).Read), desc, view)
}
