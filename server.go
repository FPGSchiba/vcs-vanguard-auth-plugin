package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	pb "github.com/FPGSchiba/vcs-vanguard-auth-plugin/vcsauthpb"
	"github.com/google/uuid"
	"github.com/sony/gobreaker/v2"
)

type VanguardAuthPluginServer struct {
	pb.UnimplementedAuthPluginServiceServer
	wixCircuitBreaker *gobreaker.CircuitBreaker[*WixLoginResponse]
	mu                sync.RWMutex
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

	if request.PluginName != pluginName {
		return &pb.ConfigureResponse{
			Success: false,
			Message: fmt.Sprintf("Plugin name mismatch: expected %s, got %s", pluginName, request.PluginName),
			Version: version,
		}, nil
	}

	return &pb.ConfigureResponse{
		Success: true,
		Message: "Configuration successful",
		Version: version,
	}, nil
}

func (s *VanguardAuthPluginServer) GetSupportedFlows(ctx context.Context, request *pb.FlowDiscoveryRequest) (*pb.FlowDiscoveryResponse, error) {
	log.Printf("Discovering Flows")
	resp := &pb.FlowDiscoveryResponse{
		Flows: []*pb.AuthFlowDefinition{
			{
				FlowId:      "vanguard_email_password",
				Description: "Vanguard email password",
				RequiredSettings: []*pb.FlowSettingDef{
					{
						Key:         "token",
						Label:       "Token",
						Description: "The API token for accessing the Vanguard Profile API",
						Type:        "string",
						Required:    true,
					},
					{
						Key:         "apiKey",
						Label:       "API Key",
						Description: "The API key for accessing the Vanguard Profile API",
						Type:        "string",
						Required:    true,
					},
					{
						Key:          "baseApiUrl",
						Label:        "Base API URL",
						Description:  "The base URL for the Vanguard Profile API",
						Type:         "string",
						Required:     true,
						DefaultValue: "https://profile.vngd.net/_functions/",
					},
				},
				Steps: []*pb.AuthStepDefinition{
					{
						StepId:          "email_password",
						StepName:        "Login",
						StepDescription: "User login with email and password",
						StepType:        "password",
						RequiredFields: []*pb.FieldDefinition{
							{
								Key:             "email",
								Label:           "Email",
								Description:     "The email address of the Vanguard Profile API",
								Type:            "string",
								Required:        true,
								ValidationRegex: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$",
							},
							{
								Key:         "password",
								Label:       "Password",
								Description: "The password of the Vanguard Profile API",
								Type:        "password",
								Required:    true,
							},
						},
					},
				},
			},
		},
	}
	return resp, nil
}

func (s *VanguardAuthPluginServer) ConfigureFlow(ctx context.Context, request *pb.ConfigureFlowRequest) (*pb.ConfigureFlowResponse, error) {
	log.Printf("Configuring flow with request: %+v\n", request)
	if request.FlowId != "vanguard_email_password" {
		return &pb.ConfigureFlowResponse{
			Success: false,
			Message: fmt.Sprintf("Flow ID mismatch: expected %s, got %s", "vanguard_email_password", request.FlowId),
		}, nil
	}

	var newConfig VanguardAuthPluginConfiguration
	var ok bool

	newConfig.Token, ok = request.Settings["token"]
	if !ok || newConfig.Token == "" {
		return &pb.ConfigureFlowResponse{
			Success: false,
			Message: "Missing or empty 'token' in settings",
		}, nil
	}
	newConfig.ApiKey, ok = request.Settings["apiKey"]
	if !ok || newConfig.ApiKey == "" {
		return &pb.ConfigureFlowResponse{
			Success: false,
			Message: "Missing or empty 'apiKey' in settings",
		}, nil
	}
	newConfig.BaseApiUrl, ok = request.Settings["baseApiUrl"]
	if !ok || newConfig.BaseApiUrl == "" {
		return &pb.ConfigureFlowResponse{
			Success: false,
			Message: "Missing or empty 'baseApiUrl' in settings",
		}, nil
	}

	s.mu.Lock()
	s.config = newConfig
	s.mu.Unlock()

	log.Printf("Flow Configuration updated successfully: %+v\n", s.config)
	return &pb.ConfigureFlowResponse{
		Success: true,
		Message: "Flow configuration successful",
	}, nil
}

func (s *VanguardAuthPluginServer) StartAuth(ctx context.Context, request *pb.StartAuthRequest) (*pb.AuthStepResponse, error) {
	log.Printf("Starting auth flow with request: %+v\n", request)

	sessionID := uuid.New().String()

	if request.FlowId != "vanguard_email_password" {
		return &pb.AuthStepResponse{
			SessionId: sessionID,
			Status:    pb.AuthStepStatus_AUTH_FAILED,
			StepResult: &pb.AuthStepResponse_ErrorMessage{
				ErrorMessage: fmt.Sprintf("Flow not supported: expected %s, got %s", "vanguard_email_password", request.FlowId),
			},
		}, nil
	}

	var email, password string
	var ok bool
	if email, ok = request.FirstStepInput["email"]; !ok || request.FirstStepInput["email"] == "" {
		return &pb.AuthStepResponse{
			SessionId: sessionID,
			Status:    pb.AuthStepStatus_AUTH_FAILED,
			StepResult: &pb.AuthStepResponse_ErrorMessage{
				ErrorMessage: fmt.Sprintf("The 'email' field is required in the first step input"),
			},
		}, nil
	}
	if password, ok = request.FirstStepInput["password"]; !ok || request.FirstStepInput["password"] == "" {
		return &pb.AuthStepResponse{
			SessionId: sessionID,
			Status:    pb.AuthStepStatus_AUTH_FAILED,
			StepResult: &pb.AuthStepResponse_ErrorMessage{
				ErrorMessage: fmt.Sprintf("The 'password' field is required in the first step input"),
			},
		}, nil
	}

	result, err := s.wixLogin(email, password)
	if err != nil {
		log.Printf(err.Error())
		return &pb.AuthStepResponse{
			SessionId: sessionID,
			Status:    pb.AuthStepStatus_AUTH_FAILED,
			StepResult: &pb.AuthStepResponse_ErrorMessage{
				ErrorMessage: err.Error(),
			},
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

	return &pb.AuthStepResponse{
		Status:    pb.AuthStepStatus_AUTH_COMPLETE,
		SessionId: sessionID,
		StepResult: &pb.AuthStepResponse_Complete{
			Complete: &pb.LoginResult{
				AvailableRoles: availableRoles,
				AvailableUnits: availableUnits,
				PlayerName:     result.Data.DisplayName,
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
		req.Header.Set("User-Agent", fmt.Sprintf("vcs-auth-plugin/%s", version))

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
