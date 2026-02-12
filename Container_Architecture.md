flowchart TB

    %% =====================
    %% USER
    %% =====================
    user["Security Researcher"]

    %% =====================
    %% ATTACKER NETWORK
    %% =====================
    subgraph AttackerNet["Attacker Network 192.168.60.0/24"]
        attacker_vm["Attacker VM - Ubuntu"]
        caldera["Caldera Server - C2"]
    end

    %% =====================
    %% CORPORATE NETWORK
    %% =====================
    subgraph CorporateNet["Corporate Network 192.168.50.0/24"]
        dc["Domain Controller - Windows Server 2019 - Passive"]
        
        subgraph WS01["Workstation WS01 - Windows 10"]
            sandcat["Caldera Agent Sandcat"]
            sysmon["Sysmon"]
            elastic_agent["Elastic Agent"]
        end
    end

    %% =====================
    %% SIEM NETWORK
    %% =====================
    subgraph SIEMNet["SIEM Network 192.168.70.0/24"]
        fleet["Fleet Server"]
        logstash["Logstash"]
        elasticsearch["Elasticsearch"]
        kibana["Kibana"]
    end

    %% =====================
    %% INFRASTRUCTURE
    %% =====================
    router["Router - Network Segmentation"]

    %% =====================
    %% USER ACCESS
    %% =====================
    user -->|Manage Attacks| caldera
    user -->|Threat Hunting| kibana

    %% =====================
    %% NETWORK ROUTING
    %% =====================
    attacker_vm --> router
    dc --> router
    WS01 --> router
    SIEMNet --> router

    %% =====================
    %% C2 TRAFFIC
    %% =====================
    caldera <-->|C2 HTTP TCP| sandcat

    %% =====================
    %% TELEMETRY FLOW
    %% =====================
    sysmon --> elastic_agent
    elastic_agent -->|Config 8220| fleet
    elastic_agent -->|Logs 5044| logstash
    logstash --> elasticsearch
    kibana --> elasticsearch
