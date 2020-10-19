/*
 * Copyright @ 2020 - present Blackvisor Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handlers

import (
	"context"
	"encoding/json"
	"log"

	api "github.com/netclave/apis/opener/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/httputils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/opener/component"
)

type Server struct {
}

func (s *Server) AddIdentityProvider(ctx context.Context, in *api.AddIdentityProviderRequest) (*api.AddIdentityProviderResponse, error) {
	identityProviderURL := in.IdentityProviderUrl
	emailOrPhone := in.EmailOrPhone

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, remoteIdentityProviderID, err := httputils.RemoteGetPublicKey(identityProviderURL, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StoreTempPublicKey(remoteIdentityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/registerPublicKey"

	data := map[string]string{}

	data["identificator"] = emailOrPhone

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, identityProviderID,
		privateKeyPEM, publicKeyPEM, publicKey, true)

	response, remoteIdentityProviderID, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	return &api.AddIdentityProviderResponse{
		Response:           response,
		IdentityProviderId: remoteIdentityProviderID,
	}, nil
}

func (s *Server) ListIdentityProviders(ctx context.Context, in *api.ListIdentityProvidersRequest) (*api.ListIdentityProvidersResponse, error) {
	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.OpenerIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ListIdentityProvidersResponse{}, err
	}

	identityProviders := []*api.IdentityProvider{}

	for _, identityProvider := range identityProvidersMap {
		identityProviderObj := &api.IdentityProvider{
			Url: identityProvider.IdentificatorURL,
			Id:  identityProvider.IdentificatorID,
		}

		identityProviders = append(identityProviders, identityProviderObj)
	}

	return &api.ListIdentityProvidersResponse{
		IdentityProviders: identityProviders,
	}, nil
}

func (s *Server) ConfirmIdentityProvider(ctx context.Context, in *api.ConfirmIdentityProviderRequest) (*api.ConfirmIdentityProviderResponse, error) {
	identityProviderURL := in.IdentityProviderUrl
	identityProviderID := in.IdentityProviderId
	code := in.ConfirmationCode
	openerName := in.OpenerName

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, err := cryptoStorage.RetrieveTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/confirmPublicKey"

	data := map[string]string{}

	data["confirmationCode"] = code
	data["identificatorType"] = cryptoutils.IDENTIFICATOR_TYPE_OPENER
	data["identificatorName"] = openerName

	firewallID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, firewallID,
		privateKeyPEM, publicKeyPEM, publicKey, true)

	response, _, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	log.Println("Response: " + response)

	if response != "\"Identificator confirmed\"" {
		log.Println("Do not add identificators")
		return &api.ConfirmIdentityProviderResponse{
			Response: response,
		}, nil
	}

	_, err = cryptoStorage.DeleteTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StorePublicKey(identityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	identificatorObject := &cryptoutils.Identificator{}
	identificatorObject.IdentificatorID = identityProviderID
	identificatorObject.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER
	identificatorObject.IdentificatorURL = identityProviderURL

	err = cryptoStorage.AddIdentificator(identificatorObject)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(identificatorObject, component.OpenerIdentificator)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(component.OpenerIdentificator, identificatorObject)

	if err != nil {
		log.Println(err.Error())
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	return &api.ConfirmIdentityProviderResponse{
		Response: response,
	}, nil
}

type IPPortProtocols struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	Protocols string `json:"protocols"`
}

func ListOpenerRulesInternal(identificator string) ([]IPPortProtocols, error) {
	cryptoStorage := component.CreateCryptoStorage()

	result := []IPPortProtocols{}

	identityProviders, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.OpenerIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		return nil, err
	}

	for _, identityProvider := range identityProviders {
		if identificator == "all" || identificator == identityProvider.IdentificatorID {
			publicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)

			if err != nil {
				return nil, err
			}
			openersURL := identityProvider.IdentificatorURL + "/listOpenerIPs"

			log.Println("Url: " + openersURL)

			openerID := component.ComponentIdentificatorID
			privateKeyPEM := component.ComponentPrivateKey
			publicKeyPEM := component.ComponentPublicKey

			request, err := jsonutils.SignAndEncryptResponse("", openerID,
				privateKeyPEM, publicKeyPEM, publicKey, false)

			response, _, _, err := httputils.MakePostRequest(openersURL, request, true, component.ComponentPrivateKey, cryptoStorage)

			if err != nil {
				log.Println("Error: " + err.Error())
				return nil, err
			}

			log.Println("Response: " + response)

			rulesForIdentityProvider := &[]IPPortProtocols{}

			err = json.Unmarshal([]byte(response), rulesForIdentityProvider)

			if err != nil {
				log.Println("Error: " + err.Error())
				return nil, err
			}

			for _, rule := range *rulesForIdentityProvider {
				result = append(result, rule)
			}
		}
	}

	return result, nil
}

func (s *Server) ListOpenerRules(ctx context.Context, in *api.ListOpenerRulesRequest) (*api.ListOpenerRulesResponse, error) {
	identityProviderID := in.IdentityProviderId

	result := []string{}

	rules, err := ListOpenerRulesInternal(identityProviderID)

	if err != nil {
		return &api.ListOpenerRulesResponse{}, err
	}

	for _, rule := range rules {
		ruleString := rule.IP + " " + rule.Port + " " + rule.Protocols
		result = append(result, ruleString)
	}

	return &api.ListOpenerRulesResponse{
		Rules: result,
	}, nil
}
