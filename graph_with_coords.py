coordinates = {
    'A': (27.7172, 85.3240),  
    'B': (27.7007, 85.3001),  
    'C': (27.6730, 85.3134),  
    'D': (27.7148, 85.3442),  
    'E': (27.6869, 85.3134),  
    'F': (27.7250, 85.3150)   
}

graph = {
    'A': {'B': 2.5, 'F': 1.0},
    'B': {'A': 2.5, 'C': 3.0, 'D': 4.5},
    'C': {'B': 3.0, 'E': 1.5, 'D': 2.8},
    'D': {'B': 4.5, 'C': 2.8, 'F': 3.5},
    'E': {'C': 1.5},
    'F': {'A': 1.0, 'D': 3.5}
}

# testing
emergency_services = {
    "hospitals": [
        {"name": "City General Hospital", "lat": 27.705, "lng": 85.33},
        {"name": "Valley Health Clinic", "lat": 27.685, "lng": 85.325}
    ],
    "police_stations": [
        {"name": "Central Police HQ", "lat": 27.71, "lng": 85.31},
        {"name": "District Police Office", "lat": 27.69, "lng": 85.34}
    ],
    "charging_stations": [
        {"name": "EV Fast Charge Point", "lat": 27.72, "lng": 85.30}
    ],
    "petrol_stations": [
        {"name": "National Petrol Pump", "lat": 27.675, "lng": 85.305}
    ]
}
# Ensure all nodes in graph keys are in coordinates
for node in graph:
    if node not in coordinates:
        print(f"CRITICAL WARNING: Node '{node}' from graph is MISSING in coordinates dictionary!")
    for neighbor in graph[node]:
        if neighbor not in coordinates:
            print(f"CRITICAL WARNING: Neighbor node '{neighbor}' (of '{node}') from graph is MISSING in coordinates dictionary!")
        if neighbor not in graph: # Also check if neighbor is a top-level key in graph for consistency
             print(f"CRITICAL WARNING: Neighbor node '{neighbor}' (of '{node}') from graph is not a top-level key in graph itself!")