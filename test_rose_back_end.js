// node.js, do login then get users etc.. needs async

let axios = require('axios');

axios.post('/api/login', {
    email: 'j@j.com',
    password: 'passwords'
  })
  .then(function (response) {
    console.log(response);
  })
  .catch(function (error) {
    console.log(error);
  });

