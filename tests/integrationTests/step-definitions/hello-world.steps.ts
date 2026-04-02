import { Given, When, Then } from '@cucumber/cucumber';
import assert from 'node:assert';

let name: string;
let greeting: string;

Given('I have a name {string}', (givenName: string) => {
  name = givenName;
});

When('I greet the name', () => {
  greeting = `Hello, ${name}!`;
});

Then('the greeting should be {string}', (expectedResult: string) => {
  assert.strictEqual(greeting, expectedResult);
});
