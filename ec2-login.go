package main

import (
    "context"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
    "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func main() {
    ctx := context.TODO()
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        log.Fatalf("unable to load SDK config, %v", err)
    }

    ec2Client := ec2.NewFromConfig(cfg)
    smClient := secretsmanager.NewFromConfig(cfg)

    // 1) Ask about including stopped instances
    var includeStopped bool
    fmt.Print("Include stopped instances? (yes/no): ")
    var includeInput string
    fmt.Scanln(&includeInput)
    includeStopped = strings.ToLower(includeInput) == "yes"

    // 2) Ask whether to search by Instance ID or Name tag
    var searchByID bool
    fmt.Print("Search by Instance ID? (yes/no): ")
    var searchInput string
    fmt.Scanln(&searchInput)
    searchByID = strings.ToLower(searchInput) == "yes"

    fmt.Print("Enter the search term (ID or name): ")
    var searchTerm string
    fmt.Scanln(&searchTerm)

    instances := listInstances(ctx, ec2Client, includeStopped, searchTerm, searchByID)
    if len(instances) == 0 {
        fmt.Println("No matching instances found.")
        return
    }

    for i, inst := range instances {
        fmt.Printf("%d) Name: %s, Instance ID: %s, State: %s\n",
            i+1, getInstanceName(inst), *inst.InstanceId, inst.State.Name)
    }

    fmt.Print("Enter the number of the instance to log into: ")
    var selectedIndex int
    fmt.Scanln(&selectedIndex)
    if selectedIndex < 1 || selectedIndex > len(instances) {
        fmt.Println("Invalid selection.")
        return
    }

    sshIntoInstance(ctx, ec2Client, smClient, instances[selectedIndex-1])
}

// --- EC2 List & Name helpers (unchanged) ---

func listInstances(ctx context.Context, client *ec2.Client, includeStopped bool, searchTerm string, searchByID bool) []ec2Types.Instance {
    filters := []ec2Types.Filter{}
    if searchByID && searchTerm != "" {
        filters = append(filters, ec2Types.Filter{
            Name:   aws.String("instance-id"),
            Values: []string{searchTerm},
        })
    } else if searchTerm != "" {
        filters = append(filters, ec2Types.Filter{
            Name:   aws.String("tag:Name"),
            Values: []string{"*" + searchTerm + "*"},
        })
    }
    if !includeStopped {
        filters = append(filters, ec2Types.Filter{
            Name:   aws.String("instance-state-name"),
            Values: []string{"running"},
        })
    }

    input := &ec2.DescribeInstancesInput{ Filters: filters }
    var instances []ec2Types.Instance
    paginator := ec2.NewDescribeInstancesPaginator(client, input)
    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            log.Fatalf("failed to get page: %v", err)
        }
        for _, res := range page.Reservations {
            instances = append(instances, res.Instances...)
        }
    }
    return instances
}

func getInstanceName(instance ec2Types.Instance) string {
    for _, tag := range instance.Tags {
        if *tag.Key == "Name" {
            return *tag.Value
        }
    }
    return "No Name"
}

// --- SSH + Key retrieval ---

func sshIntoInstance(ctx context.Context, ec2Client *ec2.Client, smClient *secretsmanager.Client, instance ec2Types.Instance) {
    instanceID := *instance.InstanceId

    // Start if stopped
    if instance.State.Name == ec2Types.InstanceStateNameStopped {
        fmt.Printf("Instance %s is stopped. Starting...\n", instanceID)
        _, err := ec2Client.StartInstances(ctx, &ec2.StartInstancesInput{
            InstanceIds: []string{instanceID},
        })
        if err != nil {
            log.Fatalf("Failed to start instance: %v", err)
        }
        waiter := ec2.NewInstanceRunningWaiter(ec2Client)
        if err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}}, 5*time.Minute); err != nil {
            log.Fatalf("Error waiting for instance to start: %v", err)
        }
    }

    // Prompt for key source
    fmt.Print("Fetch SSH key from AWS Secrets Manager? (yes/no): ")
    var smInput string
    fmt.Scanln(&smInput)
    useSecrets := strings.ToLower(smInput) == "yes"

    var keyPath string
    if useSecrets {
        var err error
        keyPath, err = getKeyFromSecrets(ctx, smClient, *instance.KeyName)
        if err != nil {
            log.Fatalf("Error retrieving key from Secrets Manager: %v", err)
        }
        // ensure cleanup
        defer os.Remove(keyPath)
    } else {
        keyPath = findKeyPathLocal(*instance.KeyName)
        if keyPath == "" {
            fmt.Printf("No matching SSH key found locally for KeyName %s\n", *instance.KeyName)
            return
        }
    }

    // Finally SSH in
    cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-i", keyPath, "ec2-user@"+*instance.PrivateIpAddress)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        log.Fatalf("SSH command failed: %v", err)
    }
}

func findKeyPathLocal(keyName string) string {
    sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
    files, err := os.ReadDir(sshDir)
    if err != nil {
        log.Fatalf("Cannot read SSH directory: %v", err)
    }
    for _, f := range files {
        if strings.HasPrefix(f.Name(), keyName) && strings.HasSuffix(f.Name(), ".pem") {
            return filepath.Join(sshDir, f.Name())
        }
    }
    return ""
}

func getKeyFromSecrets(ctx context.Context, smClient *secretsmanager.Client, secretName string) (string, error) {
    out, err := smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
        SecretId: aws.String(secretName),
    })
    if err != nil {
        return "", err
    }

    // Determine whether it's string or binary
    var pemBytes []byte
    if out.SecretString != nil {
        pemBytes = []byte(*out.SecretString)
    } else {
        pemBytes = out.SecretBinary
    }

    // Write to temp file
    tmpFile, err := ioutil.TempFile("", "ec2-key-*.pem")
    if err != nil {
        return "", err
    }
    path := tmpFile.Name()
    if _, err := tmpFile.Write(pemBytes); err != nil {
        tmpFile.Close()
        return "", err
    }
    tmpFile.Close()

    // Restrict permissions
    if err := os.Chmod(path, 0600); err != nil {
        return "", err
    }
    return path, nil
}
