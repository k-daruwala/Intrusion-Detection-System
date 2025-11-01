import numpy as np
import pandas as pd
from datetime import datetime
import random
import time
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class PacketGenerator:
    
    def __init__(self):
        self.source_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', 
                          '203.0.113.45', '198.51.100.78', '192.168.1.150']
        self.dest_ips = ['192.168.1.1', '8.8.8.8', '1.1.1.1']
        self.ports = [80, 443, 22, 3306, 8080, 21, 23, 3389, 445, 135]
        self.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        self.attack_types = ['DDoS', 'Port Scan', 'SQL Injection', 
                            'Brute Force', 'Malware', 'Normal']
        
    def generate_packet(self):
        is_malicious = random.random() < 0.20  
        
        packet = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': random.choice(self.source_ips),
            'dest_ip': random.choice(self.dest_ips),
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice(self.ports),
            'protocol': random.choice(self.protocols),
            'packet_size': random.randint(64, 1500),
            'ttl': random.randint(64, 255),
            'flags': random.randint(0, 255),
            'packet_count': random.randint(1, 100) if is_malicious else random.randint(1, 10),
            'byte_count': random.randint(1000, 100000) if is_malicious else random.randint(100, 5000),
            'duration': random.uniform(0.1, 10.0) if is_malicious else random.uniform(0.01, 1.0),
            'attack_type': random.choice(self.attack_types[:-1]) if is_malicious else 'Normal',
            'is_malicious': 1 if is_malicious else 0
        }
        
        return packet

class MLModels:
    
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Decision Tree': DecisionTreeClassifier(random_state=42),
            'SVM': SVC(kernel='rbf', random_state=42, probability=True),
            'Neural Network': MLPClassifier(hidden_layer_sizes=(100, 50), 
                                           max_iter=500, random_state=42)
        }
        self.scaler = StandardScaler()
        self.trained_models = {}
        
    def prepare_features(self, packets_df):
        feature_cols = ['source_port', 'dest_port', 'packet_size', 'ttl', 
                       'flags', 'packet_count', 'byte_count', 'duration']
        return packets_df[feature_cols]
    
    def train_models(self, packets_df):
        print("\n" + "="*60)
        print("TRAINING MACHINE LEARNING MODELS")
        print("="*60)
        
        X = self.prepare_features(packets_df)
        y = packets_df['is_malicious']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        results = {}
        
        for name, model in self.models.items():
            print(f"\nTraining {name}...")
            start_time = time.time()
            
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            
            training_time = time.time() - start_time
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'training_time': training_time
            }
            
            print(f"  ✓ Accuracy:  {accuracy*100:.2f}%")
            print(f"  ✓ Precision: {precision*100:.2f}%")
            print(f"  ✓ Recall:    {recall*100:.2f}%")
            print(f"  ✓ F1-Score:  {f1*100:.2f}%")
            print(f"  ✓ Training Time: {training_time:.2f}s")
        
        self.trained_models = results
        return results
    
    def predict(self, packet_features, model_name='Random Forest'):
        if model_name not in self.trained_models:
            return None, 0.0
        
        model = self.trained_models[model_name]['model']
        packet_scaled = self.scaler.transform([packet_features])
        
        prediction = model.predict(packet_scaled)[0]
        confidence = model.predict_proba(packet_scaled)[0][1]  
        
        return prediction, confidence

class IntrusionDetectionSystem:
    
    def __init__(self):
        self.packet_generator = PacketGenerator()
        self.ml_models = MLModels()
        self.alerts = []
        self.stats = {
            'total_packets': 0,
            'malicious_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'attack_types': defaultdict(int)
        }
        self.selected_model = 'Random Forest'
        
    def generate_training_data(self, n_packets=1000):
        print(f"\nGenerating {n_packets} packets for training...")
        packets = [self.packet_generator.generate_packet() for _ in range(n_packets)]
        df = pd.DataFrame(packets)
        print(f"✓ Generated {len(df)} packets")
        print(f"  - Normal traffic: {len(df[df['is_malicious']==0])}")
        print(f"  - Malicious traffic: {len(df[df['is_malicious']==1])}")
        return df
    
    def train_system(self, n_packets=1000):
        training_data = self.generate_training_data(n_packets)
        results = self.ml_models.train_models(training_data)
        return results
    
    def analyze_packet(self, packet):
        features = [
            packet['source_port'],
            packet['dest_port'],
            packet['packet_size'],
            packet['ttl'],
            packet['flags'],
            packet['packet_count'],
            packet['byte_count'],
            packet['duration']
        ]
        
        prediction, confidence = self.ml_models.predict(features, self.selected_model)
        
        return {
            'packet': packet,
            'predicted_malicious': prediction,
            'confidence': confidence,
            'actual_malicious': packet['is_malicious']
        }
    
    def generate_alert(self, analysis):
        packet = analysis['packet']
        confidence = analysis['confidence']
        
        severity = 'CRITICAL' if confidence > 0.9 else 'HIGH' if confidence > 0.7 else 'MEDIUM'
        
        alert = {
            'timestamp': packet['timestamp'],
            'severity': severity,
            'attack_type': packet['attack_type'],
            'source_ip': packet['source_ip'],
            'dest_ip': packet['dest_ip'],
            'dest_port': packet['dest_port'],
            'confidence': confidence * 100,
            'action': 'BLOCKED'
        }
        
        self.alerts.append(alert)
        return alert
    
    def monitor_traffic(self, duration=30, packet_rate=2):
        print("\n" + "="*60)
        print("STARTING REAL-TIME NETWORK MONITORING")
        print("="*60)
        print(f"Model: {self.selected_model}")
        print(f"Duration: {duration} seconds")
        print(f"Packet Rate: {packet_rate} packets/second")
        print("\nPress Ctrl+C to stop monitoring\n")
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                packet = self.packet_generator.generate_packet()
                analysis = self.analyze_packet(packet)
                
                self.stats['total_packets'] += 1
                
                if analysis['predicted_malicious'] == 1:
                    self.stats['malicious_detected'] += 1
                    
                    if analysis['actual_malicious'] == 1:
                        self.stats['true_positives'] += 1
                        self.stats['attack_types'][packet['attack_type']] += 1
                        
                        alert = self.generate_alert(analysis)
                        
                        print(f"🚨 [{alert['severity']}] ALERT DETECTED!")
                        print(f"   Time: {alert['timestamp']}")
                        print(f"   Type: {alert['attack_type']}")
                        print(f"   Source: {alert['source_ip']} → {alert['dest_ip']}:{alert['dest_port']}")
                        print(f"   Confidence: {alert['confidence']:.1f}%")
                        print(f"   Action: {alert['action']}")
                        print("-" * 60)
                    else:
                        self.stats['false_positives'] += 1
                
                time.sleep(1.0 / packet_rate)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user.")
        
        self.print_summary()
    
    def print_summary(self):
        print("\n" + "="*60)
        print("MONITORING SUMMARY")
        print("="*60)
        print(f"Total Packets Analyzed: {self.stats['total_packets']}")
        print(f"Threats Detected: {self.stats['malicious_detected']}")
        print(f"True Positives: {self.stats['true_positives']}")
        print(f"False Positives: {self.stats['false_positives']}")
        
        if self.stats['true_positives'] > 0:
            print(f"\nDetection Rate: {(self.stats['true_positives']/self.stats['malicious_detected'])*100:.1f}%")
        
        if self.stats['attack_types']:
            print("\nAttack Types Detected:")
            for attack, count in sorted(self.stats['attack_types'].items(), 
                                       key=lambda x: x[1], reverse=True):
                print(f"  - {attack}: {count}")
        
        print("\n" + "="*60)
        print(f"Total Alerts Generated: {len(self.alerts)}")
        print("="*60)
    
    def list_recent_alerts(self, n=5):
        print(f"\nLast {n} Security Alerts:")
        print("-" * 60)
        
        for alert in self.alerts[-n:]:
            print(f"[{alert['timestamp']}] {alert['severity']} - {alert['attack_type']}")
            print(f"  Source: {alert['source_ip']} → Port {alert['dest_port']}")
            print(f"  Confidence: {alert['confidence']:.1f}% | Action: {alert['action']}")
            print()

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   INTRUSION DETECTION SYSTEM (IDS) - ML POWERED          ║
    ║   Network Security Monitoring & Threat Detection         ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    ids = IntrusionDetectionSystem()
    
    print("\n[STEP 1] Training Machine Learning Models...")
    training_results = ids.train_system(n_packets=1000)
    
    best_model = max(training_results.items(), 
                    key=lambda x: x[1]['accuracy'])[0]
    ids.selected_model = best_model
    print(f"\n✓ Best Model Selected: {best_model} "
          f"(Accuracy: {training_results[best_model]['accuracy']*100:.2f}%)")
    
    print("\n[STEP 2] Starting Real-Time Monitoring...")
    time.sleep(2)
    
    ids.monitor_traffic(duration=30, packet_rate=2)
    
    if ids.alerts:
        ids.list_recent_alerts(n=5)
    
    print("\n✓ IDS Session Complete")

if __name__ == "__main__":
    main()
