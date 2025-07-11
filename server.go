package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/FPGSchiba/vcs-vanguard-auth-plugin/vcsauthpb"
	"github.com/sony/gobreaker/v2"
	"log"
	"net/http"
	"sync"
)

type VanguardAuthPluginServer struct {
	pb.UnimplementedAuthPluginServiceServer
	wixCircuitBreaker *gobreaker.CircuitBreaker[*WixLoginResponse]
	mu                sync.RWMutex
	name              string
	config            VanguardAuthPluginConfiguration
}

type VanguardAuthPluginConfiguration struct {
	Token      string `json:"token"`
	ApiKey     string `json:"apiKey"`
	BaseApiUrl string `json:"baseApiUrl"`
}

type WixLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type WixLoginResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Error   interface{}     `json:"error,omitempty"`
	Data    *WixLoginResult `json:"data,omitempty"`
}

type WixLoginResult struct {
	UserId         string          `json:"userId"`
	DisplayName    string          `json:"displayName"`
	AvailableUnits []WixUnitResult `json:"availableUnits"`
	AvailableRoles []uint8         `json:"availableRoles"`
}

type WixUnitResult struct {
	UnitId string `json:"unitId"`
	Name   string `json:"name"`
}

func NewVanguardAuthPluginServer() *VanguardAuthPluginServer {
	return &VanguardAuthPluginServer{
		mu:     sync.RWMutex{},
		config: VanguardAuthPluginConfiguration{},
		name:   "VanguardAuthPluginServer",
		wixCircuitBreaker: gobreaker.NewCircuitBreaker[*WixLoginResponse](gobreaker.Settings{
			Name: "WixLogin",
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
				return counts.Requests >= 3 && failureRatio >= 0.6
			},
		}),
	}
}

func (s *VanguardAuthPluginServer) Configure(ctx context.Context, request *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	log.Printf("Configuring VanguardAuthPluginServer with request: %+v\n", request)
	token, tokenOk := request.Settings["token"]
	apiKey, apiKeyOk := request.Settings["apiKey"]
	baseApiUrl, baseApiUrlOk := request.Settings["baseApiUrl"]
	if !tokenOk || !apiKeyOk || !baseApiUrlOk {
		return &pb.ConfigureResponse{
			Success: false,
			Message: "Missing required configuration settings: token, apiKey, or baseApiUrl",
			Version: version,
		}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = request.PluginName
	s.config.Token = token
	s.config.ApiKey = apiKey
	s.config.BaseApiUrl = baseApiUrl
	return &pb.ConfigureResponse{
		Success: true,
		Message: "Configuration successful",
		Version: version,
	}, nil
}

func (s *VanguardAuthPluginServer) Login(ctx context.Context, request *pb.ClientLoginRequest) (*pb.ServerLoginResponse, error) {
	var email, password string
	var ok bool
	if email, ok = request.Credentials["email"]; !ok || request.Credentials["email"] == "" {
		return &pb.ServerLoginResponse{
			Success:     false,
			LoginResult: &pb.ServerLoginResponse_ErrorMessage{ErrorMessage: "The 'email' field is required in credentials"},
		}, nil
	}
	if password, ok = request.Credentials["password"]; !ok || request.Credentials["password"] == "" {
		return &pb.ServerLoginResponse{
			Success:     false,
			LoginResult: &pb.ServerLoginResponse_ErrorMessage{ErrorMessage: "The 'password' field is required in credentials"},
		}, nil
	}

	result, err := s.wixLogin(email, password)
	if err != nil {
		log.Printf(err.Error())
		return &pb.ServerLoginResponse{
			Success:     false,
			LoginResult: &pb.ServerLoginResponse_ErrorMessage{ErrorMessage: err.Error()},
		}, nil
	}
	var availableRoles []uint32
	var availableUnits []*pb.UnitSelection
	for _, role := range result.Data.AvailableRoles {
		// Convert uint8 to uint32 for compatibility with the protobuf definition
		availableRoles = append(availableRoles, uint32(role))
	}
	for _, unit := range result.Data.AvailableUnits {
		availableUnits = append(availableUnits, &pb.UnitSelection{
			UnitId:   unit.UnitId,
			UnitName: unit.Name,
		})
	}

	return &pb.ServerLoginResponse{
		Success: true,
		LoginResult: &pb.ServerLoginResponse_Result{
			Result: &pb.LoginResult{
				AvailableRoles: availableRoles,
				AvailableUnits: availableUnits,
			},
		},
	}, nil
}

func (s *VanguardAuthPluginServer) wixLogin(email, password string) (*WixLoginResponse, error) {
	result, err := s.wixCircuitBreaker.Execute(func() (*WixLoginResponse, error) {
		reqBody, err := json.Marshal(WixLoginRequest{Email: email, Password: password})
		if err != nil {
			return nil, err
		}
		s.mu.RLock()
		url := fmt.Sprintf("%svcs_login?key=%s&token=%s", s.config.BaseApiUrl, s.config.ApiKey, s.config.Token)
		s.mu.RUnlock()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(reqBody)))
		req.Header.Set("Host", "profile.vngd.net")
		req.Header.Set("User-Agent", "vcs-auth-plugin/1.0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}

		var wixResp WixLoginResponse
		if err := json.NewDecoder(resp.Body).Decode(&wixResp); err != nil {
			return nil, err
		}

		return &wixResp, nil
	})
	if err != nil {
		return nil, err
	}

	if !result.Success {
		return result, fmt.Errorf("%s", result.Message)
	}

	if result.Data == nil {
		return result, fmt.Errorf("%s", result.Message)
	}

	return result, nil
}
