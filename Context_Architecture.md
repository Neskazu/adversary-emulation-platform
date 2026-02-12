flowchart TB

    %% ACTOR
    user["Security Researcher - Operator"]

    %% SYSTEM BOUNDARY
    subgraph Lab["Adversary Emulation Platform"]
        platform["Adversary Emulation Lab"]
    end

    %% RELATIONS
    user -->|Deploys Infrastructure via Vagrant and Ansible| platform
    user -->|Executes Attacks via Caldera| platform
    user -->|Monitors and Detects via Elastic Stack| platform
    user -->|Analyzes Artifacts for Forensics| platform
