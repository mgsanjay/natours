import axios from 'axios';
import { showAlert } from './alerts';

export const bookTour = async (tourId) => {
  try {
    const stripe = Stripe(
      'pk_test_51Ju5WHSGU8S676CyLJ5NJaqz2LYrYGgKcPWmjkifOqsHdxeqMKnoXT8uMIVo7Cf388HcnTjoUKooEyfrCgIsMUix00zKkNR1Nn'
    );
    //1.Get checkout session from the API
    const session = await axios(`/api/v1/bookings/checkout-session/${tourId}`);
    //2.Create checkout form + charge credit card
    await stripe.redirectToCheckout({ sessionId: session.data.session.id });
  } catch (err) {
    console.log(err);
    showAlert('error', err);
  }
};
