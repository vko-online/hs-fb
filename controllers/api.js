'use strict';
const async = require('async');
const graph = require('fbgraph');

/**
 * GET /api
 * List of API examples.
 */
exports.getApi = (req, res) => {
  res.render('api/index', {
    title: 'API Examples'
  });
};

/**
 * GET /api/facebook
 * Facebook API example.
 */
exports.getFacebook = (req, res, next) => {
  const token = req.user.tokens.find(token => token.kind === 'facebook');
  graph.setAccessToken(token.accessToken);
  async.parallel({
      getMyProfile: (done) => {
        graph.get(`${req.user.facebook}?fields=id,name,email,first_name,last_name,gender,link,locale,timezone`, (err, me) => {
          done(err, me);
        });
      },
      getMyFriends: (done) => {
        graph.get(`${req.user.facebook}/friends`, (err, friends) => {
          done(err, friends.data);
        });
      }
    },
    (err, results) => {
      if (err) {
        return next(err);
      }
      res.render('api/facebook', {
        title: 'Facebook API',
        me: results.getMyProfile,
        friends: results.getMyFriends
      });
    });
};

/**
 * GET /api/upload
 * File Upload API example.
 */

exports.getFileUpload = (req, res, next) => {
  res.render('api/upload', {
    title: 'File Upload'
  });
};

exports.postFileUpload = (req, res, next) => {
  req.flash('success', { msg: 'File was uploaded successfully.' });
  res.redirect('/api/upload');
};
