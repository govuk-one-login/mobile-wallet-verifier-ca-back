Feature: Issue reader certificate service

  Scenario: Request with an App Check JWT signed by an untrusted key pair is rejected
    Given I generate an issue reader cert request with an App Check JWT signed by an untrusted key pair
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 401 response
    And the response body indicates an invalid App Check token

  Scenario: Valid request returns a 200 response
    Given I generate a valid issue reader cert request
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 200 OK response
