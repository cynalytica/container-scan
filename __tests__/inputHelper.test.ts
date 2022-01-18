describe('Validate inputs', () => {
    test('Inputs validation should fail with no image input', () => {
        jest.isolateModules(() => {
            const mockedCore = require('@actions/core');
            let __mockInputValues = {
                'image-names': undefined,
                'token': 'token',
                'username': 'username',
                'password': 'password',
                'severity-threshold': 'HIGH',
                'run-quality-checks': 'true',
                'wont-fix-label': 'wontfix',
                'no-fix-label': 'no-fix',
                'is-fixed-label': 'fixed'
            }
            mockedCore.__setMockInputValues(__mockInputValues);
            const inputHelper = require('../src/inputHelper');
            expect(inputHelper.validateRequiredInputs).toThrow();
        });
    });

    test('Inputs should be validated successfully', () => {
        // Input validation tests need to be run in isolation because inputs are read at the time when module gets imported
        jest.isolateModules(() => {
            const mockedCore = require('@actions/core');
            let __mockInputValues = {
                'image-names': 'nginx',
                'token': 'token',
                'username': 'username',
                'password': 'password',
                'severity-threshold': 'HIGH',
                'run-quality-checks': 'true',
                'wont-fix-label': 'wontfix',
                'no-fix-label': 'no-fix',
                'is-fixed-label': 'fixed'
            }
            mockedCore.__setMockInputValues(__mockInputValues);
            const inputHelper = require('../src/inputHelper');
            expect(inputHelper.validateRequiredInputs).not.toThrow();
        });
    });
});
