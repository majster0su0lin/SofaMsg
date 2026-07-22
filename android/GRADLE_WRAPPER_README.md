# Gradle Wrapper

The `gradlew` and `gradlew.bat` scripts (plus `gradle/wrapper/`) should be generated
using the Gradle wrapper command. They are NOT checked into this repository template
because they contain binary files (gradle-wrapper.jar) that should be generated fresh.

## To generate the wrapper:

```bash
cd android/
gradle wrapper --gradle-version 8.5
```

This creates:
- `gradlew` (Unix shell script)
- `gradlew.bat` (Windows batch script)
- `gradle/wrapper/gradle-wrapper.jar`
- `gradle/wrapper/gradle-wrapper.properties`

## In CI:

The GitHub Actions workflow expects `gradlew` to exist. Either:
1. Generate and commit the wrapper files, OR
2. Add a CI step that runs `gradle wrapper` before `./gradlew assembleDebug`

Option 1 is the standard convention for Android projects.

## Gradle version compatibility:

| AGP Version | Minimum Gradle |
|-------------|----------------|
| 8.2.x       | 8.2            |
| 8.3.x       | 8.4            |

We use AGP 8.2.2, so Gradle 8.2+ is required. We recommend Gradle 8.5.
