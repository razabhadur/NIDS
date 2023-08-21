import scapy.all as scapy
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import socket

# Sniff network packets
def sniff_packets(interface, count=1000):
    packets = scapy.sniff(iface=interface, count=count)
    return packets

# Extract features from packets
def extract_features(packet):
    # Extract relevant packet features (example: source/destination IP, port numbers, protocol)
    # Return a list of extracted features
    pass  # Replace with your feature extraction logic

# Train a Random Forest classifier
def train_classifier(features, labels):
    classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    classifier.fit(features, labels)
    return classifier

# Real-time packet monitoring and classification
def monitor_and_classify(interface, classifier, destination_ip):
    while True:
        packet = scapy.sniff(iface=interface, count=1)[0]
        packet_features = extract_features(packet)
        if packet_features:
            packet_features = [packet_features]  # Convert to a list for prediction
            prediction = classifier.predict(packet_features)
            if prediction == 1 and packet[scapy.IP].dst == destination_ip:
                print(f"Anomaly detected for destination IP {destination_ip}! Possible intrusion attempt.")

# Main function
def main():
    interface = "eth0"  # Specify the network interface to monitor
    domain = input("Enter the domain name: ")
    destination_ip = socket.gethostbyname(domain)
    
    packets = sniff_packets(interface)
    features = [extract_features(packet) for packet in packets]
    labels = [0] * len(features)  # Assign labels (0 for normal traffic)
    
    # Split data into training and testing sets
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size=0.2)
    
    # Train the classifier
    classifier = train_classifier(features_train, labels_train)
    
    # Make predictions
    predictions = classifier.predict(features_test)
    
    # Evaluate the model
    accuracy = accuracy_score(labels_test, predictions)
    print(f"Model accuracy: {accuracy}")

    # Start real-time monitoring and classification
    monitor_and_classify(interface, classifier, destination_ip)

if __name__ == "__main__":
    main()
