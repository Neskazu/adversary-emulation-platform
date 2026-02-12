flowchart TB

    %% =====================
    %% CALDERA SERVER
    %% =====================
    subgraph CalderaServer["Caldera Server - Python AsyncIO"]
        direction TB

        %% Core
        subgraph Core["Core System"]
            server["Web Server Aiohttp"]
            api["REST API"]
            data_svc["Data Service In Memory Storage"]
            contact_svc["Contact Service"]
            planning_svc["Planning Service"]
        end

        %% Plugins
        subgraph Plugins["Plugins"]
            stockpile["Stockpile Plugin"]
            sandcat_plugin["Sandcat Plugin"]
            manx["Manx Plugin"]
            access["Access Plugin"]
        end

        %% Internal Relations
        server --> api
        api --> data_svc
        api --> planning_svc
        
        contact_svc -->|Registers Agents| data_svc
        planning_svc -->|Reads and Writes| data_svc
        
        sandcat_plugin -->|Extends| contact_svc
        stockpile -->|Provides Abilities| data_svc
    end

    %% =====================
    %% EXTERNAL ENTITIES
    %% =====================
    agent["Sandcat Agent on Victim Host"]
    user["Operator Browser"]

    %% =====================
    %% DATA FLOW
    %% =====================
    user -->|HTTP 8888| server
    agent -->|Beacon HTTP| contact_svc
    planning_svc -->|Generates Tasks| agent
