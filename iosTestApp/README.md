# KSafe iOS Test App

This is a test iOS application that demonstrates the usage of the KSafe Kotlin Multiplatform library with Flow support.

## Features

- Creates a KSafe instance with encrypted preferences
- Observes a Flow for the "test" preference key
- Updates the value using `putDirect` method
- Displays real-time updates on screen when the value changes
- Provides buttons to:
  - Update with custom text
  - Generate and set a random string value

## Setup

1. Build the KSafe framework first:
   ```bash
   cd ..
   ./gradlew :ksafe:linkDebugFrameworkIosSimulatorArm64
   ```

2. Open the Xcode project:
   ```bash
   open KSafeTestApp.xcodeproj
   ```

3. Select a simulator target and run the app

## How It Works

The app demonstrates:
- **KSafe initialization**: Creates a KSafe instance with a custom file name
- **Flow observation**: Uses `getFlow()` to observe changes to the "test" key
- **Direct updates**: Uses `putDirect()` to immediately update values
- **Flow emissions**: Shows how updates trigger Flow emissions that update the UI

## UI Components

- **Current Value Display**: Shows the latest value from the Flow
- **Text Input**: Enter custom values to store
- **Update Button**: Stores the entered value
- **Random Value Button**: Generates and stores a random string
- **Timestamp**: Shows when the value was last updated

## Implementation Notes

The app includes a simplified Flow-to-SwiftUI bridge that:
- Collects Kotlin Flow emissions
- Converts them to SwiftUI observable updates
- Handles proper cleanup on deinitialization

This demonstrates basic integration between Kotlin Multiplatform Flow and SwiftUI's reactive system.