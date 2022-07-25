// Code generated by MockGen. DO NOT EDIT.
// Source: service.go

// Package service is a generated GoMock package.
package service

import (
	reflect "reflect"

	model "github.com/authgear/authgear-server/pkg/api/model"
	identity "github.com/authgear/authgear-server/pkg/lib/authn/identity"
	loginid "github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	config "github.com/authgear/authgear-server/pkg/lib/config"
	gomock "github.com/golang/mock/gomock"
)

// MockLoginIDIdentityProvider is a mock of LoginIDIdentityProvider interface.
type MockLoginIDIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockLoginIDIdentityProviderMockRecorder
}

// MockLoginIDIdentityProviderMockRecorder is the mock recorder for MockLoginIDIdentityProvider.
type MockLoginIDIdentityProviderMockRecorder struct {
	mock *MockLoginIDIdentityProvider
}

// NewMockLoginIDIdentityProvider creates a new mock instance.
func NewMockLoginIDIdentityProvider(ctrl *gomock.Controller) *MockLoginIDIdentityProvider {
	mock := &MockLoginIDIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockLoginIDIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLoginIDIdentityProvider) EXPECT() *MockLoginIDIdentityProviderMockRecorder {
	return m.recorder
}

// CheckDuplicated mocks base method.
func (m *MockLoginIDIdentityProvider) CheckDuplicated(uniqueKey string, standardClaims map[model.ClaimName]string, userID string) (*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckDuplicated", uniqueKey, standardClaims, userID)
	ret0, _ := ret[0].(*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CheckDuplicated indicates an expected call of CheckDuplicated.
func (mr *MockLoginIDIdentityProviderMockRecorder) CheckDuplicated(uniqueKey, standardClaims, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckDuplicated", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).CheckDuplicated), uniqueKey, standardClaims, userID)
}

// Create mocks base method.
func (m *MockLoginIDIdentityProvider) Create(i *identity.LoginID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockLoginIDIdentityProviderMockRecorder) Create(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).Create), i)
}

// Delete mocks base method.
func (m *MockLoginIDIdentityProvider) Delete(i *identity.LoginID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockLoginIDIdentityProviderMockRecorder) Delete(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).Delete), i)
}

// Get mocks base method.
func (m *MockLoginIDIdentityProvider) Get(userID, id string) (*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", userID, id)
	ret0, _ := ret[0].(*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockLoginIDIdentityProviderMockRecorder) Get(userID, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).Get), userID, id)
}

// GetByValue mocks base method.
func (m *MockLoginIDIdentityProvider) GetByValue(loginIDValue string) ([]*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByValue", loginIDValue)
	ret0, _ := ret[0].([]*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByValue indicates an expected call of GetByValue.
func (mr *MockLoginIDIdentityProviderMockRecorder) GetByValue(loginIDValue interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByValue", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).GetByValue), loginIDValue)
}

// GetMany mocks base method.
func (m *MockLoginIDIdentityProvider) GetMany(ids []string) ([]*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMany", ids)
	ret0, _ := ret[0].([]*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMany indicates an expected call of GetMany.
func (mr *MockLoginIDIdentityProviderMockRecorder) GetMany(ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMany", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).GetMany), ids)
}

// List mocks base method.
func (m *MockLoginIDIdentityProvider) List(userID string) ([]*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", userID)
	ret0, _ := ret[0].([]*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockLoginIDIdentityProviderMockRecorder) List(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).List), userID)
}

// ListByClaim mocks base method.
func (m *MockLoginIDIdentityProvider) ListByClaim(name, value string) ([]*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListByClaim", name, value)
	ret0, _ := ret[0].([]*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByClaim indicates an expected call of ListByClaim.
func (mr *MockLoginIDIdentityProviderMockRecorder) ListByClaim(name, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByClaim", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).ListByClaim), name, value)
}

// New mocks base method.
func (m *MockLoginIDIdentityProvider) New(userID string, loginID identity.LoginIDSpec, options loginid.CheckerOptions) (*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", userID, loginID, options)
	ret0, _ := ret[0].(*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockLoginIDIdentityProviderMockRecorder) New(userID, loginID, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).New), userID, loginID, options)
}

// Update mocks base method.
func (m *MockLoginIDIdentityProvider) Update(i *identity.LoginID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockLoginIDIdentityProviderMockRecorder) Update(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).Update), i)
}

// WithValue mocks base method.
func (m *MockLoginIDIdentityProvider) WithValue(iden *identity.LoginID, value string, options loginid.CheckerOptions) (*identity.LoginID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithValue", iden, value, options)
	ret0, _ := ret[0].(*identity.LoginID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WithValue indicates an expected call of WithValue.
func (mr *MockLoginIDIdentityProviderMockRecorder) WithValue(iden, value, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithValue", reflect.TypeOf((*MockLoginIDIdentityProvider)(nil).WithValue), iden, value, options)
}

// MockOAuthIdentityProvider is a mock of OAuthIdentityProvider interface.
type MockOAuthIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockOAuthIdentityProviderMockRecorder
}

// MockOAuthIdentityProviderMockRecorder is the mock recorder for MockOAuthIdentityProvider.
type MockOAuthIdentityProviderMockRecorder struct {
	mock *MockOAuthIdentityProvider
}

// NewMockOAuthIdentityProvider creates a new mock instance.
func NewMockOAuthIdentityProvider(ctrl *gomock.Controller) *MockOAuthIdentityProvider {
	mock := &MockOAuthIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockOAuthIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOAuthIdentityProvider) EXPECT() *MockOAuthIdentityProviderMockRecorder {
	return m.recorder
}

// CheckDuplicated mocks base method.
func (m *MockOAuthIdentityProvider) CheckDuplicated(standardClaims map[model.ClaimName]string, userID string) (*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckDuplicated", standardClaims, userID)
	ret0, _ := ret[0].(*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CheckDuplicated indicates an expected call of CheckDuplicated.
func (mr *MockOAuthIdentityProviderMockRecorder) CheckDuplicated(standardClaims, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckDuplicated", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).CheckDuplicated), standardClaims, userID)
}

// Create mocks base method.
func (m *MockOAuthIdentityProvider) Create(i *identity.OAuth) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockOAuthIdentityProviderMockRecorder) Create(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).Create), i)
}

// Delete mocks base method.
func (m *MockOAuthIdentityProvider) Delete(i *identity.OAuth) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockOAuthIdentityProviderMockRecorder) Delete(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).Delete), i)
}

// Get mocks base method.
func (m *MockOAuthIdentityProvider) Get(userID, id string) (*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", userID, id)
	ret0, _ := ret[0].(*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockOAuthIdentityProviderMockRecorder) Get(userID, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).Get), userID, id)
}

// GetByProviderSubject mocks base method.
func (m *MockOAuthIdentityProvider) GetByProviderSubject(provider config.ProviderID, subjectID string) (*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByProviderSubject", provider, subjectID)
	ret0, _ := ret[0].(*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByProviderSubject indicates an expected call of GetByProviderSubject.
func (mr *MockOAuthIdentityProviderMockRecorder) GetByProviderSubject(provider, subjectID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByProviderSubject", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).GetByProviderSubject), provider, subjectID)
}

// GetByUserProvider mocks base method.
func (m *MockOAuthIdentityProvider) GetByUserProvider(userID string, provider config.ProviderID) (*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByUserProvider", userID, provider)
	ret0, _ := ret[0].(*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByUserProvider indicates an expected call of GetByUserProvider.
func (mr *MockOAuthIdentityProviderMockRecorder) GetByUserProvider(userID, provider interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByUserProvider", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).GetByUserProvider), userID, provider)
}

// GetMany mocks base method.
func (m *MockOAuthIdentityProvider) GetMany(ids []string) ([]*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMany", ids)
	ret0, _ := ret[0].([]*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMany indicates an expected call of GetMany.
func (mr *MockOAuthIdentityProviderMockRecorder) GetMany(ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMany", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).GetMany), ids)
}

// List mocks base method.
func (m *MockOAuthIdentityProvider) List(userID string) ([]*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", userID)
	ret0, _ := ret[0].([]*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockOAuthIdentityProviderMockRecorder) List(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).List), userID)
}

// ListByClaim mocks base method.
func (m *MockOAuthIdentityProvider) ListByClaim(name, value string) ([]*identity.OAuth, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListByClaim", name, value)
	ret0, _ := ret[0].([]*identity.OAuth)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByClaim indicates an expected call of ListByClaim.
func (mr *MockOAuthIdentityProviderMockRecorder) ListByClaim(name, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByClaim", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).ListByClaim), name, value)
}

// New mocks base method.
func (m *MockOAuthIdentityProvider) New(userID string, provider config.ProviderID, subjectID string, profile, claims map[string]interface{}) *identity.OAuth {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", userID, provider, subjectID, profile, claims)
	ret0, _ := ret[0].(*identity.OAuth)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockOAuthIdentityProviderMockRecorder) New(userID, provider, subjectID, profile, claims interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).New), userID, provider, subjectID, profile, claims)
}

// Update mocks base method.
func (m *MockOAuthIdentityProvider) Update(i *identity.OAuth) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockOAuthIdentityProviderMockRecorder) Update(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).Update), i)
}

// WithUpdate mocks base method.
func (m *MockOAuthIdentityProvider) WithUpdate(iden *identity.OAuth, rawProfile, claims map[string]interface{}) *identity.OAuth {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithUpdate", iden, rawProfile, claims)
	ret0, _ := ret[0].(*identity.OAuth)
	return ret0
}

// WithUpdate indicates an expected call of WithUpdate.
func (mr *MockOAuthIdentityProviderMockRecorder) WithUpdate(iden, rawProfile, claims interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithUpdate", reflect.TypeOf((*MockOAuthIdentityProvider)(nil).WithUpdate), iden, rawProfile, claims)
}

// MockAnonymousIdentityProvider is a mock of AnonymousIdentityProvider interface.
type MockAnonymousIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockAnonymousIdentityProviderMockRecorder
}

// MockAnonymousIdentityProviderMockRecorder is the mock recorder for MockAnonymousIdentityProvider.
type MockAnonymousIdentityProviderMockRecorder struct {
	mock *MockAnonymousIdentityProvider
}

// NewMockAnonymousIdentityProvider creates a new mock instance.
func NewMockAnonymousIdentityProvider(ctrl *gomock.Controller) *MockAnonymousIdentityProvider {
	mock := &MockAnonymousIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockAnonymousIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAnonymousIdentityProvider) EXPECT() *MockAnonymousIdentityProviderMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockAnonymousIdentityProvider) Create(i *identity.Anonymous) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockAnonymousIdentityProviderMockRecorder) Create(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).Create), i)
}

// Delete mocks base method.
func (m *MockAnonymousIdentityProvider) Delete(i *identity.Anonymous) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockAnonymousIdentityProviderMockRecorder) Delete(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).Delete), i)
}

// Get mocks base method.
func (m *MockAnonymousIdentityProvider) Get(userID, id string) (*identity.Anonymous, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", userID, id)
	ret0, _ := ret[0].(*identity.Anonymous)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockAnonymousIdentityProviderMockRecorder) Get(userID, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).Get), userID, id)
}

// GetByKeyID mocks base method.
func (m *MockAnonymousIdentityProvider) GetByKeyID(keyID string) (*identity.Anonymous, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByKeyID", keyID)
	ret0, _ := ret[0].(*identity.Anonymous)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByKeyID indicates an expected call of GetByKeyID.
func (mr *MockAnonymousIdentityProviderMockRecorder) GetByKeyID(keyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByKeyID", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).GetByKeyID), keyID)
}

// GetMany mocks base method.
func (m *MockAnonymousIdentityProvider) GetMany(ids []string) ([]*identity.Anonymous, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMany", ids)
	ret0, _ := ret[0].([]*identity.Anonymous)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMany indicates an expected call of GetMany.
func (mr *MockAnonymousIdentityProviderMockRecorder) GetMany(ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMany", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).GetMany), ids)
}

// List mocks base method.
func (m *MockAnonymousIdentityProvider) List(userID string) ([]*identity.Anonymous, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", userID)
	ret0, _ := ret[0].([]*identity.Anonymous)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockAnonymousIdentityProviderMockRecorder) List(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).List), userID)
}

// ListByClaim mocks base method.
func (m *MockAnonymousIdentityProvider) ListByClaim(name, value string) ([]*identity.Anonymous, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListByClaim", name, value)
	ret0, _ := ret[0].([]*identity.Anonymous)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByClaim indicates an expected call of ListByClaim.
func (mr *MockAnonymousIdentityProviderMockRecorder) ListByClaim(name, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByClaim", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).ListByClaim), name, value)
}

// New mocks base method.
func (m *MockAnonymousIdentityProvider) New(userID, keyID string, key []byte) *identity.Anonymous {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", userID, keyID, key)
	ret0, _ := ret[0].(*identity.Anonymous)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockAnonymousIdentityProviderMockRecorder) New(userID, keyID, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockAnonymousIdentityProvider)(nil).New), userID, keyID, key)
}

// MockBiometricIdentityProvider is a mock of BiometricIdentityProvider interface.
type MockBiometricIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockBiometricIdentityProviderMockRecorder
}

// MockBiometricIdentityProviderMockRecorder is the mock recorder for MockBiometricIdentityProvider.
type MockBiometricIdentityProviderMockRecorder struct {
	mock *MockBiometricIdentityProvider
}

// NewMockBiometricIdentityProvider creates a new mock instance.
func NewMockBiometricIdentityProvider(ctrl *gomock.Controller) *MockBiometricIdentityProvider {
	mock := &MockBiometricIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockBiometricIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBiometricIdentityProvider) EXPECT() *MockBiometricIdentityProviderMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockBiometricIdentityProvider) Create(i *identity.Biometric) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockBiometricIdentityProviderMockRecorder) Create(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).Create), i)
}

// Delete mocks base method.
func (m *MockBiometricIdentityProvider) Delete(i *identity.Biometric) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockBiometricIdentityProviderMockRecorder) Delete(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).Delete), i)
}

// Get mocks base method.
func (m *MockBiometricIdentityProvider) Get(userID, id string) (*identity.Biometric, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", userID, id)
	ret0, _ := ret[0].(*identity.Biometric)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockBiometricIdentityProviderMockRecorder) Get(userID, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).Get), userID, id)
}

// GetByKeyID mocks base method.
func (m *MockBiometricIdentityProvider) GetByKeyID(keyID string) (*identity.Biometric, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByKeyID", keyID)
	ret0, _ := ret[0].(*identity.Biometric)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByKeyID indicates an expected call of GetByKeyID.
func (mr *MockBiometricIdentityProviderMockRecorder) GetByKeyID(keyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByKeyID", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).GetByKeyID), keyID)
}

// GetMany mocks base method.
func (m *MockBiometricIdentityProvider) GetMany(ids []string) ([]*identity.Biometric, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMany", ids)
	ret0, _ := ret[0].([]*identity.Biometric)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMany indicates an expected call of GetMany.
func (mr *MockBiometricIdentityProviderMockRecorder) GetMany(ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMany", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).GetMany), ids)
}

// List mocks base method.
func (m *MockBiometricIdentityProvider) List(userID string) ([]*identity.Biometric, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", userID)
	ret0, _ := ret[0].([]*identity.Biometric)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockBiometricIdentityProviderMockRecorder) List(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).List), userID)
}

// ListByClaim mocks base method.
func (m *MockBiometricIdentityProvider) ListByClaim(name, value string) ([]*identity.Biometric, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListByClaim", name, value)
	ret0, _ := ret[0].([]*identity.Biometric)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByClaim indicates an expected call of ListByClaim.
func (mr *MockBiometricIdentityProviderMockRecorder) ListByClaim(name, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByClaim", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).ListByClaim), name, value)
}

// New mocks base method.
func (m *MockBiometricIdentityProvider) New(userID, keyID string, key []byte, deviceInfo map[string]interface{}) *identity.Biometric {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", userID, keyID, key, deviceInfo)
	ret0, _ := ret[0].(*identity.Biometric)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockBiometricIdentityProviderMockRecorder) New(userID, keyID, key, deviceInfo interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockBiometricIdentityProvider)(nil).New), userID, keyID, key, deviceInfo)
}

// MockPasskeyIdentityProvider is a mock of PasskeyIdentityProvider interface.
type MockPasskeyIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockPasskeyIdentityProviderMockRecorder
}

// MockPasskeyIdentityProviderMockRecorder is the mock recorder for MockPasskeyIdentityProvider.
type MockPasskeyIdentityProviderMockRecorder struct {
	mock *MockPasskeyIdentityProvider
}

// NewMockPasskeyIdentityProvider creates a new mock instance.
func NewMockPasskeyIdentityProvider(ctrl *gomock.Controller) *MockPasskeyIdentityProvider {
	mock := &MockPasskeyIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockPasskeyIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPasskeyIdentityProvider) EXPECT() *MockPasskeyIdentityProviderMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockPasskeyIdentityProvider) Create(i *identity.Passkey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockPasskeyIdentityProviderMockRecorder) Create(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).Create), i)
}

// Delete mocks base method.
func (m *MockPasskeyIdentityProvider) Delete(i *identity.Passkey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", i)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockPasskeyIdentityProviderMockRecorder) Delete(i interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).Delete), i)
}

// Get mocks base method.
func (m *MockPasskeyIdentityProvider) Get(userID, id string) (*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", userID, id)
	ret0, _ := ret[0].(*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockPasskeyIdentityProviderMockRecorder) Get(userID, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).Get), userID, id)
}

// GetByAssertionResponse mocks base method.
func (m *MockPasskeyIdentityProvider) GetByAssertionResponse(assertionResponse []byte) (*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByAssertionResponse", assertionResponse)
	ret0, _ := ret[0].(*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByAssertionResponse indicates an expected call of GetByAssertionResponse.
func (mr *MockPasskeyIdentityProviderMockRecorder) GetByAssertionResponse(assertionResponse interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByAssertionResponse", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).GetByAssertionResponse), assertionResponse)
}

// GetMany mocks base method.
func (m *MockPasskeyIdentityProvider) GetMany(ids []string) ([]*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMany", ids)
	ret0, _ := ret[0].([]*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMany indicates an expected call of GetMany.
func (mr *MockPasskeyIdentityProviderMockRecorder) GetMany(ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMany", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).GetMany), ids)
}

// List mocks base method.
func (m *MockPasskeyIdentityProvider) List(userID string) ([]*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", userID)
	ret0, _ := ret[0].([]*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockPasskeyIdentityProviderMockRecorder) List(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).List), userID)
}

// ListByClaim mocks base method.
func (m *MockPasskeyIdentityProvider) ListByClaim(name, value string) ([]*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListByClaim", name, value)
	ret0, _ := ret[0].([]*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByClaim indicates an expected call of ListByClaim.
func (mr *MockPasskeyIdentityProviderMockRecorder) ListByClaim(name, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByClaim", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).ListByClaim), name, value)
}

// New mocks base method.
func (m *MockPasskeyIdentityProvider) New(userID string, creationOptions *model.WebAuthnCreationOptions, attestationResponse []byte) (*identity.Passkey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", userID, creationOptions, attestationResponse)
	ret0, _ := ret[0].(*identity.Passkey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockPasskeyIdentityProviderMockRecorder) New(userID, creationOptions, attestationResponse interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockPasskeyIdentityProvider)(nil).New), userID, creationOptions, attestationResponse)
}
