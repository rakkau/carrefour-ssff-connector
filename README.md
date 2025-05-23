# midpoint-ssff-connector
The Success Factors Connector serves as a bridge between midPoint and the HR area, utilizing SAP Success Factors.

Key functionalities include:

- Bi-Directional Synchronization: Effortlessly syncs a vast amount of user information between Success Factors and midPoint.
- Event Handling: Manages user onboarding, modifications, and offboarding events with precision.
- Scheduled Task: Ensures real-time data synchronization. Any modification in Success Factors reflects promptly in midPoint, maintaining data accuracy.
- Authentication Flexibility: Supports both "OAuth" and "Basic" authentication methods, enhancing security and adaptability for diverse enterprise requirements.

## Build
Install JDK 11+ and maven3 then build:

`mvn clean package`

After successful the build, you can find midpoint-ssff-connector-*.jar in target directory.