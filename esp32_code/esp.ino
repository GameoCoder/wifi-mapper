#include "WiFi.h"

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  Serial.println("ESP32 WiFi Scanner Ready");
}

void loop() {
  Serial.println("Scanning for networks...");
  int n = WiFi.scanNetworks();
  if (n == 0) {
    Serial.println("No networks found.");
  } else {
    Serial.print(n);
    Serial.println(" networks found:");
    for (int i = 0; i < n; ++i) {
      Serial.printf("%d: %s (-%d dBm) MAC: %s | Ch: %d | Enc: %d\n", i + 1,
                    WiFi.SSID(i).c_str(), abs(WiFi.RSSI(i)),
                    WiFi.BSSIDstr(i).c_str(), WiFi.channel(i),
                    WiFi.encryptionType(i));
      delay(10);
    }
  }
  Serial.println("-----------------------");
  delay(5000);
}