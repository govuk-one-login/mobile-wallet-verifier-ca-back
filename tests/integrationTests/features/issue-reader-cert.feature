Feature: Issue reader certificate service

  Scenario: Request with an App Check JWT signed by an untrusted key pair returns a 401 response
    Given I generate an issue reader cert request with an App Check JWT signed by an untrusted key pair
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 401 unauthorized response
    And the response body contains a JWT signature error message

  Scenario: Valid request returns a 200 response
    Given I generate a valid issue reader cert request
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 200 OK response
