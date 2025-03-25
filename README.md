# 🗺️Impossible Travel Detection🗺️

![image](https://github.com/user-attachments/assets/bcfb3c35-2859-4f29-ab20-ef052c381477)

**Alert Description:** 
An alert was triggered due to logins from the same account in different states within a short timeframe. We will investigate to determine whether this is a true positive or a false alarm. Let’s begin.

**Query used to trigger alert:**

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
<br>

![image](https://github.com/user-attachments/assets/706bf38e-d93b-4c6a-8d4f-1207f0243124)

<br>

**Investigative Query:**
Using the query below we dived into each login's specific city, state to see if the travel times between each login were plausable.

<br> 

```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "716b2d6147813e60bec83b77c77dde914dc594eed46238b5513609b69e0680cf@lognpacific.com"
| project
    TimeGenerated,
    UserPrincipalName,
    City = tostring(parse_json(LocationDetails).city),
    State = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
```

<br> 

![image](https://github.com/user-attachments/assets/3efb0c6c-1d35-4b85-9ed8-54f4eac9fbf8)

## Conclusion 
It was determined that the alert was a TRUE POSITIVE. The User logged in from San Jose, Californa and Boydton, Virgina within about 30 minutes from each other, which should not be possible.

## Containment, Eradication, and Recovery

  - Isolate affected systems to prevent further damage.
    - Deactivate Account and notify the users manager
   
  - Look to see if the bad actor was able to pivot to other devices or make any changes while logged on.

## Post-Incident Activities
  - Update policies and tools to prevent recurrence.
    - Geofencing 

  - Document findings and lessons learned.
    - Record notes within the incident.

